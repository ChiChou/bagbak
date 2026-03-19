import ObjC from "frida-objc-bridge";
import Controller, { type Packet } from "frida-remote-stream";
import type { ExtensionInfo, MachOInfo, MachOTasks } from "./shared.js";
import { getApi, nsError } from "./shared.js";

const MH_MAGIC_64 = 0xfeedfacf;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const HEADER_SIZE_64 = 32;
const O_RDONLY = 0;
const STREAM_CHUNK = 2 * 1024 * 1024;

const EXCLUDE_DIRS = new Set(["SC_Info", "_CodeSignature"]);
const EXCLUDE_FILES = new Set([
  "iTunesMetadata.plist",
  "embedded.mobileprovision",
]);

function fileMgr() {
  return ObjC.classes.NSFileManager.defaultManager();
}

function parseMachO(path: string): MachOInfo | null {
  const { open, close, read } = getApi();
  const fd = open(Memory.allocUtf8String(path), O_RDONLY) as number;
  if (fd < 0) return null;

  try {
    const hdr = Memory.alloc(HEADER_SIZE_64);
    if ((read(fd, hdr, HEADER_SIZE_64) as number) < HEADER_SIZE_64) return null;
    if (hdr.readU32() !== MH_MAGIC_64) return null;

    const type = hdr.add(12).readU32();
    const ncmds = hdr.add(16).readU32();
    const sizeOfCmds = hdr.add(20).readU32();

    const cmds = Memory.alloc(sizeOfCmds);
    if ((read(fd, cmds, sizeOfCmds) as number) < sizeOfCmds) return null;

    const result: MachOInfo = {
      type,
      encrypt: { offset: 0, size: 0, id: 0 },
      offset: 0,
    };

    for (let off = 0, i = 0; i < ncmds && off + 8 <= sizeOfCmds; i++) {
      const cmd = cmds.add(off).readU32();
      const cmdsize = cmds.add(off + 4).readU32();
      if (cmd === LC_ENCRYPTION_INFO_64) {
        result.encrypt = {
          offset: cmds.add(off + 8).readU32(),
          size: cmds.add(off + 12).readU32(),
          id: cmds.add(off + 16).readU32(),
        };
        result.offset = off + HEADER_SIZE_64;
      }
      off += cmdsize;
    }

    return result;
  } finally {
    close(fd);
  }
}

function scanDir(root: string, dir: string, tasks: MachOTasks): void {
  const items = fileMgr().contentsOfDirectoryAtPath_error_(dir, NULL);
  if (!items) return;

  for (let i = 0; i < items.count(); i++) {
    const name: string = items.objectAtIndex_(i).toString();
    const full = dir + "/" + name;

    const pIsDir = Memory.alloc(Process.pointerSize);
    pIsDir.writeU8(0);
    if (!fileMgr().fileExistsAtPath_isDirectory_(full, pIsDir)) continue;

    if (pIsDir.readU8()) {
      if (!EXCLUDE_DIRS.has(name)) scanDir(root, full, tasks);
    } else {
      const info = parseMachO(full);
      if (info && info.encrypt.id !== 0) {
        tasks[full.substring(root.length + 1)] = info;
      }
    }
  }
}

function removeExcludedDirs(dir: string): void {
  const items = fileMgr().contentsOfDirectoryAtPath_error_(dir, NULL);
  if (!items) return;

  for (let i = 0; i < items.count(); i++) {
    const name: string = items.objectAtIndex_(i).toString();
    const full = dir + "/" + name;

    const pIsDir = Memory.alloc(Process.pointerSize);
    pIsDir.writeU8(0);
    if (!fileMgr().fileExistsAtPath_isDirectory_(full, pIsDir)) continue;
    if (!pIsDir.readU8()) continue;

    if (EXCLUDE_DIRS.has(name)) {
      fileMgr().removeItemAtPath_error_(full, NULL);
    } else {
      removeExcludedDirs(full);
    }
  }
}

rpc.exports = {
  prepare(bundlePath: string, bundleId: string) {
    const { NSTemporaryDirectory } = getApi();
    const tmp: string = new ObjC.Object(NSTemporaryDirectory()).toString();
    const bundleName = bundlePath.split("/").pop()!;
    const base = tmp + ".bagbak-" + bundleName;
    const payloadDir = base + "/Payload";
    const root = payloadDir + "/" + bundleName;

    fileMgr().removeItemAtPath_error_(base, NULL);

    nsError((e) =>
      fileMgr().createDirectoryAtPath_withIntermediateDirectories_attributes_error_(
        payloadDir,
        true,
        NULL,
        e,
      ),
    );

    nsError((e) => fileMgr().copyItemAtPath_toPath_error_(bundlePath, root, e));

    removeExcludedDirs(root);
    for (const f of EXCLUDE_FILES) {
      fileMgr().removeItemAtPath_error_(root + "/" + f, NULL);
    }

    const tasks: MachOTasks = {};
    scanDir(root, root, tasks);

    ObjC.classes.NSBundle.bundleWithPath_(
      "/System/Library/Frameworks/CoreServices.framework/",
    ).load();

    const app =
      ObjC.classes.LSApplicationProxy.applicationProxyForIdentifier_(bundleId);
    if (!app) throw new Error(`app ${bundleId} not found`);

    const extensions: ExtensionInfo[] = [];
    const plugins = app.plugInKitPlugins();
    for (let i = 0; i < plugins.count(); i++) {
      const plugin = plugins.objectAtIndex_(i);
      const plist = plugin.infoPlist();
      const exec: string = plist.objectForKey_("CFBundleExecutable").toString();
      const path: string = plist.objectForKey_("Path").toString();
      extensions.push({
        id: plugin.bundleIdentifier().toString(),
        path,
        exec,
        abs: path + "/" + exec,
      });
    }

    const mainBinary: string = app.bundleExecutable().toString();

    return { base, root, tasks, extensions, mainBinary };
  },

  zip(base: string) {
    const payloadDir = base + "/Payload";
    const zipDest = base + "/app.ipa";

    const coordinator =
      ObjC.classes.NSFileCoordinator.alloc().initWithFilePresenter_(null);
    const folderURL = ObjC.classes.NSURL.fileURLWithPath_(payloadDir);

    const block = new ObjC.Block({
      retType: "void",
      argTypes: ["object"],
      implementation(newURL: ObjC.Object) {
        nsError((e) =>
          fileMgr().copyItemAtPath_toPath_error_(
            newURL.path().toString(),
            zipDest,
            e,
          ),
        );
      },
    });

    const NSFileCoordinatorReadingForUploading = 1 << 3;

    nsError((e) =>
      coordinator.coordinateReadingItemAtURL_options_error_byAccessor_(
        folderURL,
        NSFileCoordinatorReadingForUploading,
        e,
        block,
      ),
    );

    return zipDest;
  },

  stream(filePath: string) {
    const { open, close, read } = getApi();

    const attrs = fileMgr().attributesOfItemAtPath_error_(filePath, NULL);
    const fileSize: number = attrs
      .objectForKey_("NSFileSize")
      .unsignedLongLongValue();
    console.log("stream:", filePath, "size:", fileSize);

    const fd = open(Memory.allocUtf8String(filePath), O_RDONLY) as number;
    if (fd < 0) throw new Error("Failed to open " + filePath);

    const controller = new Controller();

    // agent → host: send stanza requests
    controller.events.on("send", (packet: Packet) => {
      const buf = packet.data as Buffer | null;
      send(
        packet.stanza,
        buf
          ? (buf.buffer.slice(
              buf.byteOffset,
              buf.byteOffset + buf.byteLength,
            ) as ArrayBuffer)
          : null,
      );
    });

    // host → agent: receive stanza responses
    function listen() {
      recv("stream", (message: any, data: ArrayBuffer | null) => {
        controller.receive({ stanza: message, data: data as any });
        listen();
      });
    }
    listen();

    const sink = controller.open("ipa", { size: fileSize });

    return new Promise<boolean>((resolve, reject) => {
      sink.on("error", reject);
      sink.on("finish", () => {
        close(fd);
        resolve(true);
      });

      const buf = Memory.alloc(STREAM_CHUNK);
      let remaining = fileSize;

      function writeNext() {
        while (remaining > 0) {
          const n = Math.min(STREAM_CHUNK, remaining);
          const bytesRead = read(fd, buf, n) as number;
          if (bytesRead <= 0) {
            sink.end();
            return;
          }

          const chunk = Buffer.from(buf.readByteArray(bytesRead)!);
          remaining -= bytesRead;

          if (remaining <= 0) {
            sink.end(chunk);
            return;
          }

          if (!sink.write(chunk)) {
            sink.once("drain", writeNext);
            return;
          }
        }
        sink.end();
      }

      writeNext();
    });
  },

  cleanup(base: string) {
    fileMgr().removeItemAtPath_error_(base, NULL);
  },
};
