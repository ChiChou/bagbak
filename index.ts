import { EventEmitter } from "events";
import { createWriteStream, type PathLike } from "fs";
import { resolve } from "path";
import { Transform } from "stream";
import { pipeline } from "stream/promises";

import chalk from "chalk";
import type { Application, Device, Script } from "frida";
import Controller from "frida-remote-stream";

import { debug, directoryExists, readFromPackage, sleep } from "./lib/utils.ts";

const MH_EXECUTE = 0x2;
const MAX_DECRYPT_RETRIES = 3;

export type DumpMode = "all" | "main" | "extensions" | "binaries";

interface Extension {
  id: string;
  path: string;
  abs: string;
}

interface BinaryInfo {
  type: number;
  [key: string]: unknown;
}

interface PrepareResult {
  base: string;
  root: string;
  tasks: Record<string, BinaryInfo>;
  extensions: Extension[];
  mainBinary: string;
}

export class BagBak extends EventEmitter {
  #device: Device;
  #app: Application;

  constructor(device: Device, app: Application) {
    super();
    this.#app = app;
    this.#device = device;
  }

  get bundle() {
    return this.#app.identifier;
  }

  get remote() {
    return this.#app.parameters.path as string;
  }

  async #attach() {
    const session = await this.#device.attach("SpringBoard");
    const code = await readFromPackage("agent", "dist", "springboard.js");
    const script = await session.createScript(code.toString());
    script.logHandler = (level, text) =>
      console.log("[springboard]", level, text);
    await script.load();
    return { session, script };
  }

  async #decrypt(
    pid: number,
    remoteRoot: string,
    root: string,
    binaries: Record<string, BinaryInfo>,
    isExtension: boolean,
  ) {
    const session = await this.#device.attach(pid);
    const code = await readFromPackage("agent", "dist", "app.js");
    const script = await session.createScript(code.toString());

    script.logHandler = (level, text) => debug("[app]", level, text);
    script.message.connect((message) => {
      if (message.type === "send" && message.payload?.event === "patch") {
        this.emit("patch", message.payload.name);
        script.post({ type: "ack" });
      }
    });

    await script.load();

    if (isExtension) {
      await script.exports.hookExtensionMain();
    }

    await this.#device.resume(pid);
    const result = await script.exports.dump(
      remoteRoot,
      root,
      binaries,
      isExtension,
    );
    debug("dump result =>", result);

    await script.unload();
    await session.detach();
  }

  async #decryptWithRetry(
    label: string,
    spawnTarget: string | string[],
    remoteRoot: string,
    root: string,
    binaries: Record<string, BinaryInfo>,
    isExtension: boolean,
  ): Promise<void> {
    let lastError: unknown;
    for (let attempt = 1; attempt <= MAX_DECRYPT_RETRIES; attempt++) {
      const pid = await this.#device.spawn(spawnTarget);
      debug("spawned", label, "pid =>", pid);
      try {
        await this.#decrypt(pid, remoteRoot, root, binaries, isExtension);
        return;
      } catch (e) {
        lastError = e;
        if (attempt < MAX_DECRYPT_RETRIES) {
          this.emit(
            "status",
            `Retry ${attempt}/${MAX_DECRYPT_RETRIES} for ${label}...`,
          );
          await sleep(1000);
        }
      } finally {
        await this.#device.kill(pid).catch(() => {});
      }
    }
    throw lastError;
  }

  async #pull(coordScript: Script, zipPath: string, destPath: string) {
    const controller = new Controller();

    const done = new Promise<void>((resolve, reject) => {
      controller.events.on("stream", (source: any) => {
        const totalSize: number = source.details.size;
        this.emit("streaming", totalSize);

        let transferred = 0;
        const progress = new Transform({
          transform(chunk, _encoding, callback) {
            transferred += chunk.length;
            this.push(chunk);
            callback();
          },
        });

        const interval = setInterval(() => {
          this.emit("progress", transferred, totalSize);
        }, 200);

        pipeline(source, progress, createWriteStream(destPath)).then(
          () => {
            clearInterval(interval);
            this.emit("progress", totalSize, totalSize);
            resolve();
          },
          (err) => {
            clearInterval(interval);
            reject(err);
          },
        );
      });
    });

    controller.events.on("send", (packet: any) => {
      coordScript.post({ type: "stream", ...packet.stanza }, packet.data);
    });

    const handler = (message: any, data: any) => {
      if (
        message.type === "send" &&
        typeof message.payload?.name === "string"
      ) {
        controller.receive({ stanza: message.payload, data });
      }
    };
    coordScript.message.connect(handler);

    try {
      await coordScript.exports.stream(zipPath);
      await done;
    } finally {
      coordScript.message.disconnect(handler);
    }
  }

  async pack(suggested?: PathLike, mode: DumpMode = "all", removeKeys: string[] = []): Promise<string> {
    const { session: coordSession, script: coordScript } = await this.#attach();

    try {
      this.emit("status", "Preparing app bundle...");
      const { base, root, tasks, extensions, mainBinary } =
        (await coordScript.exports.prepare(
          this.remote,
          this.bundle,
          removeKeys,
        )) as PrepareResult;

      const taskCount = Object.keys(tasks).length;
      debug("root", root);
      debug("tasks", taskCount, "encrypted binaries");
      debug("extensions", extensions.length);

      if (taskCount === 0) {
        this.emit("status", "No encrypted binaries found");
      }

      const groupByExtensions = new Map<string, Record<string, BinaryInfo>>(
        extensions.map((ext) => [ext.id, {}]),
      );
      const binariesForMain: Record<string, BinaryInfo> = {};

      for (const [relative, info] of Object.entries(tasks)) {
        const absolute = this.remote + "/" + relative;
        const ext = extensions.find((ext) => absolute.startsWith(ext.path));

        if (ext) {
          debug("scope for", chalk.green(relative), "is", chalk.gray(ext.id));
          groupByExtensions.get(ext.id)![relative] = info;
        } else if (
          info.type === MH_EXECUTE &&
          absolute !== this.remote + "/" + mainBinary
        ) {
          console.error(chalk.red("Executable"), chalk.yellowBright(relative));
          console.error(
            chalk.red(
              "is not within any extension. Likely requires higher MinimumOSVersion.",
            ),
          );
          console.error(chalk.red("This binary will be left encrypted."));
        } else {
          debug("scope for", relative, "is", chalk.green("main app"));
          binariesForMain[relative] = info;
        }
      }

      const decryptMain = mode !== "extensions";
      const decryptExtensions = mode !== "main";

      if (decryptMain && Object.keys(binariesForMain).length) {
        this.emit("status", "Decrypting main app...");
        await this.#decryptWithRetry(
          "main app",
          this.bundle,
          this.remote,
          root,
          binariesForMain,
          false,
        );
      }

      if (decryptExtensions) {
        for (const [extId, binaries] of groupByExtensions.entries()) {
          if (Object.keys(binaries).length === 0) continue;

          const ext = extensions.find((e) => e.id === extId)!;
          this.emit("status", `Decrypting extension ${extId}...`);
          await this.#decryptWithRetry(
            extId,
            [ext.abs],
            this.remote,
            root,
            binaries,
            true,
          );
        }
      }

      const ver = (this.#app.parameters.version as string) || "Unknown";
      let remotePath: string;
      let defaultFilename: string;
      let ext: string;

      if (mode === "all") {
        this.emit("status", "Packaging IPA...");
        remotePath = (await coordScript.exports.zip(base)) as string;
        ext = ".ipa";
        defaultFilename = `${this.bundle}-${ver}.ipa`;
      } else {
        const files: string[] = [];
        if (mode === "main" || mode === "binaries") {
          files.push(...Object.keys(binariesForMain));
        }
        if (mode === "extensions" || mode === "binaries") {
          for (const [extId, binaries] of groupByExtensions.entries()) {
            files.push(...Object.keys(binaries));
          }
        }

        this.emit("status", `Compressing ${files.length} binaries...`);
        remotePath = (await coordScript.exports.zipFiles(
          root,
          files,
        )) as string;
        ext = ".zip";
        defaultFilename = `${this.bundle}-${ver}-${mode}.zip`;
      }

      debug("remote path:", remotePath);

      const suggestedStr = suggested?.toString();
      const dest = suggestedStr
        ? (await directoryExists(suggestedStr))
          ? suggestedStr + "/" + defaultFilename
          : suggestedStr
        : defaultFilename;

      if (ext && !dest.endsWith(ext))
        throw new Error(`Invalid filename ${dest}, expected ${ext} extension`);

      this.emit("status", "Downloading...");
      await this.#pull(coordScript, remotePath, resolve(process.cwd(), dest));

      await coordScript.exports.cleanup(base);

      return dest;
    } finally {
      await coordScript.unload().catch(() => {});
      await coordSession.detach().catch(() => {});
    }
  }
}
