import { EventEmitter } from "events";
import { mkdir, open, readFile } from "fs/promises";
import { tmpdir } from "os";
import { basename, join } from "path";

import { Device } from "frida";

import { apps } from './lib/installation.js';
import { Pull } from './lib/scp.js';
import { connect } from './lib/ssh.js';
import { directoryExists } from './lib/utils.js';
import { findEncryptedBinaries } from "./lib/scan.js";

/**
 * @typedef MessagePayload
 * @property {string} event
 */

export class Job extends EventEmitter {
  #device;
  #bundle;

  /**
   * @type {import("frida").Application | null}
   */
  #app = null;

  /**
   * 
   * @param {Device} device 
   * @param {string} bundleId
   */
  constructor(device, bundleId) {
    super();

    this.#bundle = bundleId;
    this.#device = device;
  }

  /**
   * get all alls
   * @returns {Promise<import("frida").Application[]>}
   */
  async list() {
    // frida bug: this is empty on rootless iOS 16
    const list1 = this.#device.enumerateApplications();
    if (list1.length) return list1;

    // fallback
    const list2 = await apps(this.#device);
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

  async findApp() {
    const apps = await this.list();
    const app = apps.find(app => app.name === this.#bundle || app.identifier === this.#bundle);
    this.app = app;
    if (!app)
      throw new Error(`Unable to find app: ${this.#bundle}`);
  }

  async copyToLocal(src, dest) {
    const client = await connect(this.#device);

    try {
      const pull = new Pull(client, src, dest, true);
      await pull.start();
    } finally {
      client.end();
    }
  }

  /**
   * 
   * @param {import("fs").PathLike} dest path
   * @param {boolean} override whether to override existing files
   */
  async dumpTo(dest, override) {
    const parent = join(dest, this.#bundle, 'Payload');
    if (await directoryExists(parent) && !override)
      throw new Error('Destination already exists');

    await mkdir(parent, { recursive: true });

    // fist, copy directory to local
    const remoteRoot = this.app.parameters.path;
    console.log(remoteRoot);
    console.log('copy to', parent);

    const localRoot = join(parent, basename(remoteRoot));
    if (!await directoryExists(localRoot)) {
      await this.copyToLocal(remoteRoot, parent);
    }

    // find all encrypted binaries
    const map = await findEncryptedBinaries(localRoot);
    const agentScript = await readFile(join('agent', 'tiny.js'));
    /**
     * @type {Map<string, import("fs/promises").FileHandle>}
     */
    const fileHandles = new Map();

    // execute dump
    for (const [scope, dylibs] of map.entries()) {
      const mainExecutable = [remoteRoot, scope].join('/');
      const pid = await this.#device.spawn(mainExecutable);
      console.log('pid =>', pid);
      const session = await this.#device.attach(pid);
      const script = await session.createScript(agentScript.toString());
      script.logHandler = (level, text) => {
        console.log('[script log]', level, text); // todo: color
      };

      /**
       * @param {function(msg: import("frida").Message, data: ArrayBuffer): void} handler
       */
      script.message.connect(async (message, data) => {
        if (message.type !== 'send') return;

        console.log('msg', message, data);

        /**
         * @type {MessagePayload}
         */
        const payload = message.payload;
        const key = payload.name;
        if (payload.event === 'begin') {
          console.log('patch >>', join(localRoot, key));
          const fd = await open(join(localRoot, key), 'r+');
          fileHandles.set(key, fd);
        } else if (payload.event === 'trunk') {
          await fileHandles.get(key).write(data, 0, data.byteLength, payload.fileOffset);
        } else if (payload.event === 'end') {
          const fd = fileHandles.get(key);
          // remove cryptid
          const zeroFilled = Buffer.alloc(4).fill(0);
          fd.write(zeroFilled, 0, 4, payload.flagOffset);
          await fileHandles.get(key).close();
          fileHandles.delete(key);
        }

        script.post({ type: 'ack' });
      });

      await script.load();
      const result = await script.exports.newDump(remoteRoot, dylibs);
      // console.log('result =>', result);
      await script.unload();
      await session.detach();
      await this.#device.kill(pid);
    }
  }

  /**
   * 
   * @param {import("fs").PathLike} ipa path of ipa
   */
  async repack(ipa) {
    const cwd = join(tmpdir(), 'bagbak');
    await mkdir(cwd, { recursive: true });
    await this.dumpTo(cwd, true);
    // todo: zip
  }
}