#!/usr/bin/env node

import chalk from 'chalk';

import { Command } from 'commander';
import { DeviceManager, getDevice, getRemoteDevice, getUsbDevice, Device } from 'frida';

import { BagBak } from '../index.js';
import { enableDebug, enumerateApps, version } from '../lib/utils.js';

/**
 * 
 * @param {Command} cmd 
 * @returns {Promise<Device>} device
 */
function getDeviceFromOptions(cmd) {
  let count = 0;

  if (cmd.device) count++;
  if (cmd.usb) count++;
  if (cmd.remote) count++;
  if (cmd.host) count++;

  if (count === 0 || cmd.usb) {
    return getUsbDevice();
  }

  if (count > 1)
    throw new Error('Only one of --device, --usb, --remote, --host can be specified');

  if (cmd.device) {
    return getDevice(cmd.device);
  } else if (cmd.remote) {
    return getRemoteDevice();
  } else if (cmd.host) {
    const manager = new DeviceManager();
    return manager.addRemoteDevice(cmd.host);
  }
}

async function main() {
  const program = new Command();

  program
    .name('bagbak')
    .option('-l, --list', 'list apps')
    .option('-j, --json', 'output as json (only works with --list)')

    .option('-U, --usb', 'connect to USB device (default)')
    .option('-R, --remote', 'connect to remote frida-server')
    .option('-D, --device <uuid>', 'connect to device with the given ID')
    .option('-H, --host <host>', 'connect to remote frida-server on HOST')

    .option('-f, --force', 'override existing files')
    .option('-d, --debug', 'enable debug output')
    .option('-r, --raw', 'dump raw app bundle to directory (no ipa)')
    .option('-o, --output <output>', 'ipa filename or directory to dump to')
    .option('--abort-on-error', 'abort on error')
    .usage('[bundle id or name]')
    .version(await version());

  program.parse(process.argv);

  if (program.debug)
    enableDebug(true);

  const device = await getDeviceFromOptions(program);
  const info = await device.querySystemParameters();

  if (info.access !== 'full' || info.os.id !== 'ios' || info.platform !== 'darwin' || info.arch !== 'arm64') {
    console.error('This tool requires a jailbroken 64bit iOS device');
    process.exit(1);
  }

  if (program.list) {
    const apps = await enumerateApps(device);

    if (program.json) {
      console.log(JSON.stringify(apps, null, 2));
      return;
    }

    const verWidth = Math.max(...apps.map(app => app.parameters?.version?.length || 0));
    const idWidth = Math.max(...apps.map(app => app.identifier.length));

    console.log(
      chalk.gray('Version'.padStart(verWidth)),
      chalk.gray('Identifier'.padEnd(idWidth)),
      chalk.gray('Name'),
    );

    console.log(chalk.gray('─'.repeat(10 + verWidth + idWidth)));

    for (const app of apps) {
      console.log(
        chalk.yellowBright((app.parameters?.version || '').padStart(verWidth)),
        chalk.greenBright(app.identifier.padEnd(idWidth)),
        app.name
      );
    }

    return;
  }

  if (program.args.length === 1) {
    const target = program.args[0];

    const apps = await enumerateApps(device);
    const app = apps.find(app => app.name === target || app.identifier === target);
    if (!app)
      throw new Error(`Unable to find app ${target}`);

    const job = new BagBak(device, app);

    let files = 0;
    let folders = 0;

    job
      .on('mkdir', (remote) => {
        folders++;
      })
      .on('download', (remote, size) => {

      })
      .on('progress', (remote, downloaded, size) => {

      })
      .on('done', (remote) => {
        process.stdout.write(`\r${chalk.greenBright('[info]')} downloaded ${files++} files and ${folders} folders`);
      })
      .on('sshBegin', () => {
        console.log(chalk.greenBright('[info]'), 'pulling app bundle from device, please be patient');
      })
      .on('sshFinish', () => {
        process.stdout.write('\n');
        console.log(chalk.greenBright('[info]'), 'app bundle downloaded');
      })
      .on('patch', (remote) => {
        console.log(chalk.redBright('[decrypt]'), remote);
      })

    const saved = program.raw ?
      await job.dump(program.output || '.', program.force, program.abortOnError) :
      await job.pack(program.output);

    console.log(`Saved to ${chalk.yellow(saved)}`);
    return;
  }

  program.help();
}

main();