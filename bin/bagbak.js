#!/usr/bin/env node

import { Command } from 'commander';
import { DeviceManager, getDevice, getRemoteDevice, getUsbDevice } from 'frida';

import { Main } from '../index.js';
import { enumerateApps } from '../lib/utils.js';

/**
 * 
 * @param {Command} options 
 * @returns {Promise<RequireResolve('frida').Device>} device
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

    .option('-U, --usb', 'connect to USB device (default)')
    .option('-R, --remote', 'connect to remote frida-server')
    .option('-D, --device <uuid>', 'connect to device with the given ID')
    .option('-H, --host <host>', 'connect to remote frida-server on HOST')

    .option('-o, --output <output>', 'output directory', 'dump')
    .option('-f, --override', 'override existing')
    .option('-z, --zip', 'create zip archive (ipa)')
    .usage('[bundle id or name]');

  program.parse(process.argv);

  const device = await getDeviceFromOptions(program);
  const info = await device.querySystemParameters();

  if (info.access !== 'full' || info.os.id !== 'ios' || info.platform !== 'darwin' || info.arch !== 'arm64') {
    console.error('This tool requires a jailbroken 64bit iOS device');
    process.exit(1);
  }

  const job = new Main(device, program.args[0]);

  if (program.list) {
    const apps = await enumerateApps(device);
    console.table(apps.map(app => {
      return {
        'Label': app.name,
        'Bundle ID': app.identifier,
        'Version': app.parameters.version
      }
    }));

    return;
  }

  if (program.args.length === 1) {
    await job.findApp();
    await job.repack();
    return;
  }

  program.help();
}

main();