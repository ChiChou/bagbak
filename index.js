import { EventEmitter } from "events";
import { mkdir, open } from "fs/promises";
import { tmpdir } from "os";
import { basename, join, resolve } from "path";

import { Device } from "frida";

import { findEncryptedBinaries } from './lib/scan.js';
import { Pull } from './lib/scp.js';
import { connect } from './lib/ssh.js';
import { debug, directoryExists, passthrough, readAgent } from './lib/utils.js';
import zip from './lib/zip.js';

export { enumerateApps, readAgent } from './lib/utils.js';

/**
 * @typedef MessagePayload
 * @property {string} event
 */

export class Main extends EventEmitter {
  #device;
  #bundle;

  /**
   * @type {import("frida").Application | null}
   */
  #app = null;

  /**
   * 
   * @param {Device} device 
   * @param {import("frida").Application} app
   */
  constructor(device, app) {
    super();

    this.#app = app;
    this.#device = device;
  }

  async copyToLocal(src, dest) {
    const client = await connect(this.#device);

    try {
      const pull = new Pull(client, src, dest, true);
      passthrough(pull, this);
      await pull.start();
    } finally {
      client.end();
    }
  }

  get bundle() {
    return this.#app.identifier;
  }

  get remote() {
    return this.#app.parameters.path;
  }

  /**
   * 
   * @param {import("fs").PathLike} dest path
   * @param {boolean} override whether to override existing files
   * @returns {Promise<string>}
   */
  async dumpTo(dest, override) {
    const parent = join(dest, this.bundle, 'Payload');
    if (await directoryExists(parent) && !override)
      throw new Error('Destination already exists');

    await mkdir(parent, { recursive: true });

    // fist, copy directory to local
    const remoteRoot = this.remote;
    debug('remote root', remoteRoot);
    debug('copy to', parent);

    const localRoot = join(parent, basename(remoteRoot));
    this.emit('sshBegin');
    await this.copyToLocal(remoteRoot, parent);
    this.emit('sshFinish');

    // find all encrypted binaries
    const map = await findEncryptedBinaries(localRoot);
    const agentScript = await readAgent();
    /**
     * @type {Map<string, import("fs/promises").FileHandle>}
     */
    const fileHandles = new Map();

    // execute dump
    for (const [scope, dylibs] of map.entries()) {
      const mainExecutable = [remoteRoot, scope].join('/');
      const pid = await this.#device.spawn(mainExecutable);
      debug('pid =>', pid);
      const session = await this.#device.attach(pid);
      const script = await session.createScript(agentScript.toString());
      script.logHandler = (level, text) => {
        debug('[script log]', level, text); // todo: color
      };

      /**
       * @param {function(msg: import("frida").Message, data: ArrayBuffer): void} handler
       */
      script.message.connect(async (message, data) => {
        if (message.type !== 'send') return;

        debug('msg', message, data);

        /**
         * @type {MessagePayload}
         */
        const payload = message.payload;
        const key = payload.name;
        if (payload.event === 'begin') {
          this.emit('patch', key);
          debug('patch >>', join(localRoot, key));
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
      debug('result =>', result);
      await script.unload();
      await session.detach();
      await this.#device.kill(pid);
    }

    return parent;
  }

  /**
   * 
   * @param {import("fs").PathLike?} suggested path of ipa
   * @return {Promise<string>} final path of ipa
   */
  async packTo(suggested) {
    const cwd = join(tmpdir(), 'bagbak');
    await mkdir(cwd, { recursive: true });
    const payload = await this.dumpTo(cwd, true);

    debug('payload =>', payload);

    const ver = this.#app.parameters.version || 'Unknown';
    const defaultTemplate = `${this.bundle}-${ver}.ipa`;
    const ipa = suggested || defaultTemplate;

    const full = resolve(process.cwd(), ipa);
    await zip(full, payload);

    return ipa;
  }
}
