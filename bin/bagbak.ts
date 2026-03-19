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

import { BagBak } from "../index.js";
import { enableDebug, version } from "../lib/utils.js";

interface Options {
  device?: string;
  usb?: boolean;
  remote?: boolean;
  host?: string;
  debug?: boolean;
  list?: boolean;
  json?: boolean;
  output?: string;
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
    .argument("[target]", "bundle id or name")
    .version(await version());

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

  if (program.args.length === 1) {
    const target = program.args[0];

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
          `Streaming ${(totalSize / 1024 / 1024).toFixed(1)} MB...`,
        );
      });

    const saved = await job.pack(opts.output);
    console.log(`Saved to ${chalk.yellow(saved)}`);
    return;
  }

  program.help();
}

main();
