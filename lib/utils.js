import { Device } from 'frida';
import { readFile, stat } from 'fs/promises';

import { EventEmitter } from 'events';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

import { apps } from './installation.js';

export const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

export const directoryExists = path => stat(path)
  .then(info => info.isDirectory())
  .catch(() => false);

/**
 * 
 * @param {Device} device 
 */
export async function enumerateApps(device) {
  // frida bug: this is empty on rootless iOS 16
  const list1 = device.enumerateApplications();
  if (list1.length) return list1;

  // fallback
  const list2 = await apps(device);
  return list2.map(app => ({
    pid: 0,
    name: app.CFBundleDisplayName,
    identifier: app.CFBundleIdentifier,
    parameters: {
      version: app.CFBundleShortVersionString,
      build: app.CFBundleVersion,
      path: app.Path,
      started: false,
      frontmost: false,
      containers: [app.Container]
    }
  }));
}

/**
 * forward download events
 * @param {EventEmitter} source 
 * @param {EventEmitter} destination 
 */
export function passthrough(source, destination) {
  const events = ['download', 'mkdir', 'progress', 'done'];
  for (const event of events) {
    source.on(event, (...args) => destination.emit(event, ...args));
  }
}

/**
 * @returns {Promise<string>}
 */
export function readAgent() {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  const agent = join(__dirname, '..', 'agent', 'tiny.js');
  return readFile(agent, 'utf8');
}


const __debug = 'DEBUG' in process.env;
export function debug() {
  if (__debug)
    console.log(...arguments);
}

export function debugEnabled() {
  return __debug;
}
