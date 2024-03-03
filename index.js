import { EventEmitter } from 'events';
import { mkdir, open, rm, rename } from 'fs/promises';
import { tmpdir } from 'os';
import { basename, join, resolve } from 'path';

import { AppBundleVisitor } from './lib/scan.js';
import { Pull } from './lib/scp.js';
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

    const SpringBoardSession = await this.#device.attach('SpringBoard');
    const SpringBoardScript = await SpringBoardSession.createScript(
      await readFromPackage('agent', 'SpringBoard.js'));
    await SpringBoardScript.load();

    const pkdSession = await this.#device.attach('pkd');
    const pkdScript = await pkdSession.createScript(
      await readFromPackage('agent', 'pkd.js'));
    await pkdScript.load();
    await pkdScript.exports.skipPkdValidationFor(SpringBoardSession.pid);

    const plugins = await SpringBoardScript.exports.plugins(this.#app.identifier);

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
    const agentScript = await readFromPackage('agent', 'inject.js');

    /** @type {Map<string, import("fs/promises").FileHandle>} */
    const fileHandles = new Map();

    /**
     * @param {number} pid
     * @param {[import("fs").PathLike, import("./macho").MachO][]} dylibs
     * @param {import("fs").PathLike}
     * @returns {Promise<boolean>}
     */
    const task = async (pid, executable, dylibs) => {
      debug('pid =>', pid);
      await this.#device.resume(pid);

      const mainExecutable = join(localRoot, executable);
      debug('main executable =>', mainExecutable);

      /**
       * @type {import("frida").Session}
       */
      let session;
      try {
        session = await this.#device.attach(pid);
      } catch (e) {
        if (abortOnError) throw e;

        console.error(`Failed to attach to pid ${pid}, skipping...`);
        console.error(`Warning: Unable to dump ${dylibs.map(([path, _]) => path).join('\n')}`);
        return false;
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

      return true;
    }

    // dump main executable
    {
      const { identifier } = this.#app;
      const pid = await this.#device.spawn(identifier);
      const info = map.get(identifier);
      if (!info) throw new Error('Unable to find main executable');

      const { dylibs, executable } = info;
      await task(pid, executable, dylibs);
    }

    // dump plugins
    for (const pluginId of plugins) {
      const pid = await SpringBoardScript.exports.run(pluginId);
      const info = map.get(pluginId);
      if (!info) throw new Error(`Unable to find plugin info for ${pluginId}`);
      const { dylibs, executable } = info;
      await task(pid, executable, dylibs);
    }

    await SpringBoardScript.unload();
    await SpringBoardSession.detach();

    await pkdScript.unload();
    await pkdSession.detach();

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
