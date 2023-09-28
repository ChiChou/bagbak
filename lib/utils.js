import { readFile, stat } from 'fs/promises';

import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

import { apps } from './installation.js';

/**
 * to sleep
 * @param {number} ms 
 * @returns {Promise<void>} 
 */
export const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * 
 * @param {import('fs').PathLike} path directory to check
 * @returns {Promise<boolean>}
 */
export const directoryExists = path => stat(path)
  .then(info => info.isDirectory())
  .catch(() => false);

/**
 * 
 * @param {import("frida").Device} device 
 * @returns {Promise<import('frida').Application[]>}
 */
export async function enumerateApps(device) {
  // frida bug: this is empty on rootless iOS 16
  const list = device.enumerateApplications();
  if (list.length) return list;

  // fallback
  const fallback = await apps(device);
  return fallback.map(app => ({
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
 * read source code of agent
 * @param  {...string} components
 * @returns {Promise<string>}
 */
export function readFromPackage(...components) {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  const agent = join(__dirname, '..', ...components);
  return readFile(agent, 'utf8');
}


/**
 * read version from package.json
 * @returns {Promise<string>}
 */
export async function version() {
  const { version } = JSON.parse(await readFromPackage('package.json'));
  return version;
}


let __debug = 'DEBUG' in process.env;

/**
 * debug log
 * @param  {...any} args
 */
export function debug() {
  if (__debug)
    console.log(...arguments);
}

/**
 * @param {boolean} value set new value
 * @returns {boolean}
 */
export function enableDebug(value=undefined) {
  if (value !== undefined) __debug = value;
  return __debug;
}

/**
 * Determines if running on a rootless jailbreak
 * @param {import("frida").Device} device
 * @returns {boolean} true if rootless, false if rootful
 */
export async function isRootless(device) {
  /**
  * @type {import("frida").Session}
  */
  let session;
  try {
    session = await device.attach(1); // pid 1 is launchd and always there to inject into
  } catch(e) {
    throw new Error('Failed to attach to launchd to detect rootless/rootful');
  }
  const agentScript = await readFromPackage('agent', 'rootless.js');
  const script = await session.createScript(agentScript.toString());
  script.logHandler = (level, text) => {
    debug('[isRootless script log]', level, text); // todo: color
  };

  session.detached.connect((reason, crash) => {
    debug('isRootless session detached', reason, crash);
  });
  await script.load();
  const rootless = await script.exports.isRootless();
  debug('isRootless =>', rootless);
  await script.unload();
  await session.detach();
  return rootless;
 }
