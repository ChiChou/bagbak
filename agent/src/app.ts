import ObjC from "frida-objc-bridge";
import type { MachOTasks } from "./shared.js";
import { getApi } from "./shared.js";

const HIGH_WATER_MARK = 1024 * 1024;
const O_RDWR = 0x0002;

const EXTENSION_SYMBOLS = [
  "libxpc.dylib`xpc_main",
  "Foundation`NSExtensionMain",
  "ExtensionFoundation`EXExtensionMain",
];

rpc.exports = {
  hookExtensionMain() {
    const CFRunLoopRun =
      Process.getModuleByName("CoreFoundation").getExportByName("CFRunLoopRun");

    for (const symbol of EXTENSION_SYMBOLS) {
      const [dylib, func] = symbol.split("`");
      try {
        const p = Process.getModuleByName(dylib).getExportByName(func);
        console.log("replace function", symbol, p);
        Interceptor.replace(p, CFRunLoopRun);
      } catch (e: any) {
        console.log("skip", symbol, e.message);
      }
    }

    ObjC.schedule(ObjC.mainQueue, () => {
      console.log("mainQueue scheduled");
    });
  },

  dump(remoteRoot: string, tempRoot: string, binaries: MachOTasks, isExtension: boolean = false) {
    const { open, close, pwrite, exit } = getApi();

    for (const [relative, info] of Object.entries(binaries)) {
      console.log("decrypt", relative);

      const { offset, size } = info.encrypt;
      const absoluteOriginal = remoteRoot + "/" + relative;
      const absoluteTemp = tempRoot + "/" + relative;

      const mod = Module.load(absoluteOriginal);
      const fatOffset = Process.findRangeByAddress(mod.base)!.file!.offset;

      console.log("module =>", mod.name, mod.base, mod.size);
      console.log("encrypted =>", offset, size, "fatOffset =>", fatOffset);

      const fd = open(Memory.allocUtf8String(absoluteTemp), O_RDWR) as number;
      if (fd < 0) {
        console.error("Failed to open", absoluteTemp);
        continue;
      }

      let p = mod.base.add(offset);
      let fileOffset = offset + fatOffset;
      let remaining = size;

      while (remaining > 0) {
        const chunk = Math.min(HIGH_WATER_MARK, remaining);
        pwrite(fd, p, chunk, fileOffset);
        p = p.add(chunk);
        fileOffset += chunk;
        remaining -= chunk;
      }

      // patch LC_ENCRYPTION_INFO_64: zero out cryptoff, cryptsize, cryptid
      const zeros = Memory.alloc(12);
      pwrite(fd, zeros, 12, info.offset + 8 + fatOffset);

      close(fd);

      send({ event: "patch", name: relative });
      recv("ack", () => {}).wait();
    }

    if (isExtension) {
      ObjC.schedule(ObjC.mainQueue, () => {
        exit(0);
      });
    }

    return true;
  },
};
