import { EventEmitter } from "events";
import { createWriteStream, type PathLike } from "fs";
import { resolve } from "path";
import { pipeline } from "stream/promises";

import chalk from "chalk";
import type { Application, Device, Script } from "frida";
import Controller from "frida-remote-stream";

import { debug, directoryExists, readFromPackage } from "./lib/utils.ts";

const MH_EXECUTE = 0x2;

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

  async #pull(coordScript: Script, zipPath: string, destPath: string) {
    const controller = new Controller();

    const done = new Promise<void>((resolve, reject) => {
      controller.events.on("stream", (source: any) => {
        this.emit("streaming", source.details.size);
        pipeline(source, createWriteStream(destPath)).then(resolve, reject);
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

  async pack(suggested?: PathLike): Promise<string> {
    const { session: coordSession, script: coordScript } = await this.#attach();

    try {
      this.emit("status", "Copying app bundle on device...");
      const { base, root, tasks, extensions, mainBinary } =
        (await coordScript.exports.prepare(
          this.remote,
          this.bundle,
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

      if (Object.keys(binariesForMain).length) {
        this.emit("status", "Decrypting main app...");
        const pid = await this.#device.spawn(this.bundle);
        debug("spawned app pid =>", pid);
        try {
          await this.#decrypt(pid, this.remote, root, binariesForMain, false);
        } finally {
          await this.#device.kill(pid).catch(() => {});
        }
      }

      for (const [extId, binaries] of groupByExtensions.entries()) {
        if (Object.keys(binaries).length === 0) continue;

        const ext = extensions.find((e) => e.id === extId)!;
        this.emit("status", `Decrypting extension ${extId}...`);
        const pid = await this.#device.spawn([ext.abs]);
        debug("extension", extId, "pid =>", pid);
        try {
          await this.#decrypt(pid, this.remote, root, binaries, true);
        } finally {
          await this.#device.kill(pid).catch(() => {});
        }
      }

      this.emit("status", "Assembling IPA on device...");
      const zipPath = (await coordScript.exports.zip(base)) as string;
      debug("zip created at", zipPath);

      const ver = (this.#app.parameters.version as string) || "Unknown";
      const defaultTemplate = `${this.bundle}-${ver}.ipa`;

      const suggestedStr = suggested?.toString();
      const ipa = suggestedStr
        ? (await directoryExists(suggestedStr))
          ? suggestedStr + "/" + defaultTemplate
          : suggestedStr
        : defaultTemplate;

      if (!ipa.endsWith(".ipa"))
        throw new Error(
          `Invalid archive name ${suggested}, must end with .ipa`,
        );

      this.emit("status", "Streaming IPA from device...");
      await this.#pull(coordScript, zipPath, resolve(process.cwd(), ipa));

      await coordScript.exports.cleanup(base);

      return ipa;
    } finally {
      await coordScript.unload().catch(() => {});
      await coordSession.detach().catch(() => {});
    }
  }
}
