#!/usr/bin/env node

import chalk from "chalk";

import { Command } from "commander";
import {
  DeviceManager,
  getDevice,
  getRemoteDevice,
  getUsbDevice,
  Scope,
} from "frida";
import type { Device } from "frida";

import { BagBak, type DumpMode } from "../index.ts";
import { enableDebug, version } from "../lib/utils.ts";

const VALID_MODES = ["all", "main", "extensions", "binaries"] as const;

const MODE_ALIASES: Record<string, DumpMode> = {
  app: "main",
  ext: "extensions",
  exts: "extensions",
  executables: "binaries",
  bin: "binaries",
};

interface Options {
  device?: string;
  usb?: boolean;
  remote?: boolean;
  host?: string;
  debug?: boolean;
  list?: boolean;
  json?: boolean;
  output?: string;
  removeKeys?: string;
}

function getDeviceFromOptions(opts: Options): Promise<Device> {
  let count = 0;

  if (opts.device) count++;
  if (opts.usb) count++;
  if (opts.remote) count++;
  if (opts.host) count++;

  if (count === 0 || opts.usb) return getUsbDevice();
  if (count > 1)
    throw new Error(
      "Only one of --device, --usb, --remote, --host can be specified",
    );

  if (opts.device) return getDevice(opts.device);
  if (opts.remote) return getRemoteDevice();
  if (opts.host) {
    const manager = new DeviceManager();
    return manager.addRemoteDevice(opts.host);
  }

  return getUsbDevice();
}

async function main() {
  const program = new Command();

  program
    .name("bagbak")
    .option("-l, --list", "list apps")
    .option("-j, --json", "output as json (only works with --list)")

    .option("-U, --usb", "connect to USB device (default)")
    .option("-R, --remote", "connect to remote frida-server")
    .option("-D, --device <uuid>", "connect to device with the given ID")
    .option("-H, --host <host>", "connect to remote frida-server on HOST")

    .option("-d, --debug", "enable debug output")
    .option("-o, --output <output>", "ipa filename or directory")
    .option("--remove-keys <keys>", "additional Info.plist keys to remove (comma-separated)")
    .argument("[target]", "bundle id or name")
    .argument("[mode]", "dump mode: all, main (app), extensions (ext, exts), binaries (bin, executables)", "all")
    .version(version());

  program.parse(process.argv);

  const opts = program.opts<Options>();

  if (opts.debug) enableDebug(true);

  const device = await getDeviceFromOptions(opts);
  const info = await device.querySystemParameters();

  if (
    info.access !== "full" ||
    info.os.id !== "ios" ||
    info.platform !== "darwin" ||
    info.arch !== "arm64"
  ) {
    console.error("This tool requires a jailbroken 64bit iOS device");
    process.exit(1);
  }

  if (opts.list) {
    const apps = await device.enumerateApplications({ scope: Scope.Metadata });

    if (opts.json) {
      console.log(JSON.stringify(apps, null, 2));
      return;
    }

    const verWidth = Math.max(
      ...apps.map((app) => (app.parameters?.version as string)?.length || 0),
    );
    const idWidth = Math.max(...apps.map((app) => app.identifier.length));

    console.log(
      chalk.gray("Version".padStart(verWidth)),
      chalk.gray("Identifier".padEnd(idWidth)),
      chalk.gray("Name"),
    );

    console.log(chalk.gray("\u2500".repeat(10 + verWidth + idWidth)));

    for (const app of apps) {
      console.log(
        chalk.yellowBright(
          ((app.parameters?.version as string) || "").padStart(verWidth),
        ),
        chalk.greenBright(app.identifier.padEnd(idWidth)),
        app.name,
      );
    }

    return;
  }

  if (program.args.length >= 1) {
    const target = program.args[0];
    const rawMode = program.args[1] || "all";
    const mode = (MODE_ALIASES[rawMode] || rawMode) as DumpMode;

    if (!VALID_MODES.includes(mode)) {
      console.error(
        chalk.red(`Invalid mode "${rawMode}". Must be one of: ${VALID_MODES.join(", ")} (aliases: ${Object.keys(MODE_ALIASES).join(", ")})`),
      );
      process.exit(1);
    }

    const apps = await device.enumerateApplications({ scope: Scope.Metadata });
    const app = apps.find(
      (app) => app.name === target || app.identifier === target,
    );
    if (!app) throw new Error(`Unable to find app ${target}`);

    const job = new BagBak(device, app);

    job
      .on("status", (msg: string) => {
        console.log(chalk.greenBright("[info]"), msg);
      })
      .on("patch", (name: string) => {
        console.log(chalk.redBright("[decrypt]"), name);
      })
      .on("streaming", (totalSize: number) => {
        console.log(
          chalk.greenBright("[info]"),
          `Streaming ${(totalSize / 1024 / 1024).toFixed(1)} MB from device...`,
        );
      })
      .on("progress", (transferred: number, totalSize: number) => {
        const percent = Math.min(transferred / totalSize, 1);
        const barWidth = 30;
        const filled = Math.round(barWidth * percent);
        const bar =
          chalk.greenBright("\u2588".repeat(filled)) +
          chalk.gray("\u2591".repeat(barWidth - filled));
        const mb = (transferred / 1024 / 1024).toFixed(1);
        const totalMb = (totalSize / 1024 / 1024).toFixed(1);
        const pct = (percent * 100).toFixed(0).padStart(3);
        process.stdout.write(
          `\r  ${bar} ${pct}% ${mb}/${totalMb} MB`,
        );
        if (transferred >= totalSize) {
          process.stdout.write("\n");
        }
      });

    const removeKeys = opts.removeKeys
      ? opts.removeKeys.split(",").map((k) => k.trim())
      : [];

    const saved = await job.pack(opts.output, mode, removeKeys);
    console.log(`Saved to ${chalk.yellow(saved)}`);
    return;
  }

  program.help();
}

main();
