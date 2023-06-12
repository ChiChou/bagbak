#!/usr/bin/env node

import chalk from 'chalk';
import progress, { SingleBar } from 'cli-progress';

import { Command } from 'commander';
import { DeviceManager, getDevice, getRemoteDevice, getUsbDevice } from 'frida';

import { Main } from '../index.js';
import { debugEnabled, enumerateApps } from '../lib/utils.js';

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

    .option('-o, --output <output>', 'ipa filename')
    .usage('[bundle id or name]');

  program.parse(process.argv);

  const device = await getDeviceFromOptions(program);
  const info = await device.querySystemParameters();

  if (info.access !== 'full' || info.os.id !== 'ios' || info.platform !== 'darwin' || info.arch !== 'arm64') {
    console.error('This tool requires a jailbroken 64bit iOS device');
    process.exit(1);
  }

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
    const target = program.args[0];

    const apps = await enumerateApps(device);
    const app = apps.find(app => app.name === target || app.identifier === target);
    if (!app)
      throw new Error(`Unable to find app ${target}`);

    const job = new Main(device, app);

    /**
     * 
     * @param {number} size 
     * @returns {string} readable format
     */
    function humanFileSize(size) {
      const i = size == 0 ? 0 : Math.floor(Math.log(size) / Math.log(1024));
      const unit = ['B', 'kB', 'MB', 'GB', 'TB'][i];
      if (!unit) throw new Error('Out of range');
      const val = (size / Math.pow(1024, i)).toFixed(2);
      return `${val} ${unit}`;
    }

    /**
     * @type {SingleBar | null}
     */
    let bar = null;

    /**
     * @type {string}
     */
    let current;

    if (!debugEnabled()) {
      job
        .on('mkdir', (remote) => {
          process.stdout.write('\r' + remote);
        })
        .on('download', (remote, size) => {
          current = remote;
          process.stdout.write('\r' + remote);
  
          if (bar) bar.stop();

          if (size > 2 * 1024 * 1024) {
            const format = `${chalk.cyan('{bar}')} ${chalk.grey(' | {percentage}% | {downloaded}/{size}')} ${remote}`
            bar = new progress.SingleBar({
              format,
              barCompleteChar: '\u2588',
              barIncompleteChar: '\u2591',
            });
            bar.start(size, 0);
          }
        })
        .on('progress', (remote, downloaded, size) => {
          if (remote !== current) throw new Error('Protocol Error');
          if (!bar) return;
          bar.update(downloaded, {
            downloaded: humanFileSize(downloaded), size: humanFileSize(size)
          });
        })
        .on('done', (remote) => {
          if (remote !== current) throw new Error('Protocol Error');
          if (!bar) return;
          bar.update(bar.getTotal());
          bar.stop();
          bar = null;
        })
        .on('patch', (remote) => {
          console.log('decrypt', remote);
        })
    }

    await job.packTo(program.output);
    return;
  }

  program.help();
}

main();