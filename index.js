import { EventEmitter } from 'events';
import { mkdir, open, rm, rename } from 'fs/promises';
import { tmpdir } from 'os';
import { basename, join, resolve } from 'path';

import { AppBundleVisitor } from './lib/scan.js';
import { Pull, quote } from './lib/scp.js';
import { connect } from './lib/ssh.js';
import { debug, directoryExists, readFromPackage } from './lib/utils.js';
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
   * @type {import("ssh2").ConnectConfig}
   */
  #auth;

  /**
   * constructor
   * @param {import("frida").Device} device 
   * @param {import("frida").Application} app
   */
  constructor(device, app) {
    super();

    this.#app = app;
    this.#device = device;

    if ('SSH_USERNAME' in process.env || 'SSH_PASSWORD' in process.env) {
      const { SSH_USERNAME, SSH_PASSWORD } = process.env;
      if (!SSH_USERNAME || !SSH_PASSWORD)
        throw new Error('You have to provide both SSH_USERNAME and SSH_PASSWORD');

      this.#auth = {
        username: SSH_USERNAME,
        password: SSH_PASSWORD
      };
    } else if ('SSH_PRIVATE_KEY' in process.env) {
      throw new Error('key auth not supported yet');
    } else {
      this.#auth = {
        username: 'root',
        password: 'alpine'
      };
    }
  }

  /**
   * scp from remote to local
   * @param {string} src 
   * @param {import("fs").PathLike} dest 
   */
  async #copyToLocal(src, dest) {
    const client = await connect(this.#device, this.#auth);

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

    const client = await connect(this.#device, this.#auth);
    const cmd = `chmod +xX ${quote(path)}`;
    return new Promise((resolve, reject) => {
      client.exec(cmd, (err, stream) => {
        if (err) return reject(err);
        stream
          .on('close', (code, signal) => {
            client.end();
            resolve();

            if (code !== 0) {
              console.error(`failed to execute "${cmd}", exited with code ${code}`);
            }
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
   * @param {boolean} abortOnError whether to abort on error
   * @returns {Promise<string>}
   */
  async dump(parent, override = false, abortOnError = false) {
    if (!await directoryExists(parent))
      throw new Error('Output directory does not exist');

    // fist, copy directory to local
    const remoteRoot = this.remote;
    debug('remote root', remoteRoot);
    debug('copy to', parent);

    const localRoot = join(parent, basename(remoteRoot));
    if (await directoryExists(localRoot) && !override)
      throw new Error('Destination already exists, use -f to override');

    this.emit('sshBegin');
    await this.#copyToLocal(remoteRoot, parent);

    this.emit('sshFinish');

    const visitor = new AppBundleVisitor(localRoot);
    await visitor.removeUnwanted();
    const map = await visitor.encryptedBinaries();

    debug('encrypted binaries', map);
    const agentScript = await readFromPackage('agent', 'tiny.js');
    /**
     * @type {Map<string, import("fs/promises").FileHandle>}
     */
    const fileHandles = new Map();

    // execute dump
    for (const [scope, dylibs] of map.entries()) {
      const mainExecutable = [remoteRoot, scope].join('/');
      debug('main executable =>', mainExecutable);
      await this.#executableWorkaround(mainExecutable);

      /**
       * @type {number}
       */
      let pid;
      try {
        pid = await this.#device.spawn(mainExecutable);
      } catch(e) {
        if (abortOnError) throw e;

        console.error(`Failed to spawn executable at ${mainExecutable}, skipping...`);
        console.error(`Warning: Unable to dump ${dylibs.map(([path, _]) => path).join('\n')}`);
        continue;
      }

      debug('pid =>', pid);

      /**
       * @type {import("frida").Session}
       */
      let session;
      try {
        session = await this.#device.attach(pid);
      } catch(e) {
        if (abortOnError) throw e;

        console.error(`Failed to attach to pid ${pid}, skipping...`);
        console.error(`Warning: Unable to dump ${dylibs.map(([path, _]) => path).join('\n')}`);
        continue;
      }
      const script = await session.createScript(agentScript.toString());
      script.logHandler = (level, text) => {
        debug('[script log]', level, text); // todo: color
      };

      session.detached.connect((reason, crash) => {
        debug('session detached', reason, crash);
      });

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

    if (!ipa.endsWith('.ipa')) 
      throw new Error(`Invalid archive name ${suggested}, must end with .ipa`);

    const full = resolve(process.cwd(), ipa);
    const z = full.slice(0, -4) + '.zip';
    await zip(z, payload);
    debug('Created zip archive', z);
    await rename(z, ipa);

    return ipa;
  }
}
