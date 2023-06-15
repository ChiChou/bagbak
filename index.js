import { EventEmitter } from "events";
import { mkdir, open, rm } from "fs/promises";
import { tmpdir } from "os";
import { basename, join, resolve } from "path";

import { findEncryptedBinaries } from './lib/scan.js';
import { Pull, quote } from './lib/scp.js';
import { connect } from './lib/ssh.js';
import { debug, directoryExists, readAgent } from './lib/utils.js';
import zip from './lib/zip.js';


/**
 * @typedef MessagePayload
 * @property {string} event
 */

/**
 * main class
 */
export class BagBak extends EventEmitter {
  #device;

  /**
   * @type {import("frida").Application | null}
   */
  #app = null;

  /**
   * constructor
   * @param {import("frida").Device} device 
   * @param {import("frida").Application} app
   */
  constructor(device, app) {
    super();

    this.#app = app;
    this.#device = device;
  }

  /**
   * scp from remote to local
   * @param {string} src 
   * @param {import("fs").PathLike} dest 
   */
  async #copyToLocal(src, dest) {
    const client = await connect(this.#device);

    const pull = new Pull(client, src, dest, true);
    const events = ['download', 'mkdir', 'progress', 'done'];
    for (const event of events) {
      // delegate events
      pull.receiver.on(event, (...args) => this.emit(event, ...args));
    }

    try {
      await pull.execute();
    } finally {
      client.end();
    }
  }

  /**
   * hack: some extension is not executable
   * @param {string} path 
   * @returns 
   */
  async #executableWorkaround(path) {
    if (!path.startsWith('/private/var/containers/Bundle/Application/')) {
      return; // do not apply to system apps
    }

    const client = await connect(this.#device);
    const cmd = `chmod +xX ${quote(path)}`;
    return new Promise((resolve, reject) => {
      client.exec(cmd, (err, stream) => {
        if (err) return reject(err);
        stream
          .on('close', (code, signal) => {
            client.end();
            if (code === 0) return resolve();
            reject(new Error(`remote command "${cmd}" exited with code ${code}`));
          })
          .on('data', () => { }) // this handler is a must, otherwise the stream will hang
          .stderr.pipe(process.stderr); // proxy stderr
      });
    });
  }

  get bundle() {
    return this.#app.identifier;
  }

  get remote() {
    return this.#app.parameters.path;
  }

  /**
   * dump raw app bundle to directory (no ipa)
   * @param {import("fs").PathLike} parent path
   * @param {boolean} override whether to override existing files
   * @returns {Promise<string>}
   */
  async dump(parent, override = false) {
    if (!await directoryExists(parent))
      throw new Error('Output directory does not exist');

    // fist, copy directory to local
    const remoteRoot = this.remote;
    debug('remote root', remoteRoot);
    debug('copy to', parent);

    const localRoot = join(parent, basename(remoteRoot));
    if (await directoryExists(localRoot) && !override)
      throw new Error('Destination already exists');

    this.emit('sshBegin');
    await this.#copyToLocal(remoteRoot, parent);
    this.emit('sshFinish');

    // find all encrypted binaries
    const map = await findEncryptedBinaries(localRoot);
    debug('encrypted binaries', map);
    const agentScript = await readAgent();
    /**
     * @type {Map<string, import("fs/promises").FileHandle>}
     */
    const fileHandles = new Map();

    // execute dump
    for (const [scope, dylibs] of map.entries()) {
      const mainExecutable = [remoteRoot, scope].join('/');
      debug('main executable =>', mainExecutable);
      await this.#executableWorkaround(mainExecutable);

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

    return localRoot;
  }

  /**
   * dump and pack to ipa. if no name is provided, the bundle id and version will be used
   * @param {import("fs").PathLike?} suggested path of ipa
   * @returns {Promise<string>} final path of ipa
   */
  async pack(suggested) {
    const payload = join(tmpdir(), 'bagbak', this.bundle, 'Payload');
    await rm(payload, { recursive: true, force: true });
    await mkdir(payload, { recursive: true });
    await this.dump(payload, true);
    debug('payload =>', payload);

    const ver = this.#app.parameters.version || 'Unknown';
    const defaultTemplate = `${this.bundle}-${ver}.ipa`;

    const ipa = suggested ?
      (await directoryExists(suggested) ?
        join(suggested, defaultTemplate) :
        suggested) :
      defaultTemplate;

    const full = resolve(process.cwd(), ipa);
    await zip(full, payload);

    return ipa;
  }
}
