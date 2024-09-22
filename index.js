import { EventEmitter } from 'events';
import { mkdir, rm, rmdir, rename, open } from 'fs/promises';
import { basename, join, resolve } from 'path';

import chalk from 'chalk';

import { AppBundleVisitor } from './lib/scan.js';
import { MH_EXECUTE } from './lib/macho.js';
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
  /** @type {import("frida").Device} */
  #device;

  /** @type {import("frida").Application | null} */
  #app = null;

  /** @type {import("ssh2").ConnectConfig} */
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
        username: 'mobile',
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
      throw new Error('Destination already exists, use -f to override');

    this.emit('sshBegin');
    await this.#copyToLocal(remoteRoot, parent);

    this.emit('sshFinish');

    const visitor = new AppBundleVisitor(localRoot);
    await visitor.removeUnwanted();

    /**
     * @type {Map<string, import('./lib/macho.js').MachO>}
     */
    const tasks = new Map();
    for await (const [relative, info, _] of visitor.visitRoot()) {
      tasks.set(relative, info);
    }

    const pidChronod = await this.#device.getProcess('chronod')
      .then(proc => proc.pid)
      .catch(() => {
        throw new Error(`chronod service is not running on the device.
        At this moment, we haven't implemented the ability to start the service. 
        Please start it manually with following command on the device and try again:
        "launchctl kickstart -p user/foreground/com.apple.chronod"`);
      });

    const agentScript = await readFromPackage('agent', 'inject.js');
    const launchdScript = await readFromPackage('agent', 'runningboardd.js');

    /** @type {Map<string, import("fs/promises").FileHandle>} */
    const fileHandles = new Map();

    /**
     * @param {number} pid
     * @param {string[]} binaries
     * @returns {Promise<boolean>}
     */
    const task = async (pid, binaries) => {
      debug('pid =>', pid);

      await this.ensurePidReady(pid);  // hack

      /** @type {import("frida").Session} */
      const session = await this.#device.attach(pid);
      /** @type {import("frida").Script} */
      const script = await session.createScript(agentScript.toString());
      debug('session =>', session);

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
      const result = await script.exports.dump(remoteRoot, binaries);
      debug('result =>', result);
      await script.unload();
      await session.detach();
      await this.#device.kill(pid);

      return true;
    }

    const runningboardd = await this.#device.attach('runningboardd');
    const script = await runningboardd.createScript(launchdScript);
    await script.load();

    /** @type {ExtensionInfo[]} */
    const extensions = await script.exports.extensions(this.#app.identifier);
    debug('extensions', extensions);

    /** @type {string} */
    const mainAppBinary = this.#app.parameters.path + '/' + await script.exports.main(this.#app.identifier);
    debug('main app binary', mainAppBinary);

    /** @type {Map<string, Record<string, MachO>>} */
    const groupByExtensions = new Map(extensions.map(ext => [ext.id, {}]));

    /** @type {Record<string, MachO>} */
    const binariesForMain = {};
    for (const [relative, info] of tasks.entries()) {
      const absolute = remoteRoot + '/' + relative;
      const ext = extensions.find(ext => absolute.startsWith(ext.path));
      if (ext) {
        debug('scope for', chalk.green(relative), 'is', chalk.gray(ext.id));
        groupByExtensions.get(ext.id)[relative] = info;
        continue;
      }

      if (info.type === MH_EXECUTE && absolute !== mainAppBinary) {
        console.error(chalk.red('Executable'), chalk.yellowBright(relative));
        console.error(chalk.red('is not within any extension. It is very likely that one of the extensions requires a MinimumOSVersion'));
        console.error(chalk.red('that is higher than your OS. This will result in a binary that is left encrypted.'));
      } else {
        debug('scope for', relative, 'is', chalk.green('main app'));
        binariesForMain[relative] = info;
      }
    }

    debug('grouped by extensions', groupByExtensions);
    debug('binaries for main app', binariesForMain);

    // dump main app
    if (Object.keys(binariesForMain).length) {
      const pidApp = await script.exports.spawn(this.#app.identifier);
      debug('spawned app pid =>', pidApp);
      await task(pidApp, binariesForMain);
    }

    // dump extensions
    for (const [extId, binaries] of groupByExtensions.entries()) {
      if (Object.keys(binaries).length === 0) continue;

      const pidExtension = await script.exports.kickstart(extId, pidChronod);
      debug('extension', extId, pidExtension);
      await task(pidExtension, binaries);
    }

    await script.unload();
    await runningboardd.detach();

    return localRoot;
  }

  /**
   * hack: there is some race condition, so wait 1 sec for frida to initialize
   * need to find out the proper signal
   * @param {number} pid 
   */
  async ensurePidReady(pid) {
    for (let i = 0; i < 20; i++) {
      try {
        const session = await this.#device.attach(pid);
        await session.detach();
        return;
      } catch (error) {
        const message = `${error}`;
        if (message.includes('Timeout was reached')) {
          console.error(chalk.yellowBright(
            `For timeout error, there is an edge case that some apps from appstore incorrectly
            set the minimum os version requirement. For example WidgetKitExtension of Chrome app.
            We are not able to dump such extensions, because they can not run on your device.`))

          throw error;
        } else if (message.includes('either refused to load frida-agent, or terminated during injection')) {
          throw new Error(`Error: app process crashed, please try running the command again.
            Original error message: ${error}`);
        } else if (!message.includes('libSystem.B.dylib')) {
          throw error; // ignore libSystem.B.dylib not found error
        }
        debug('retry', i, error);
      }
      // sleep
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    // maxium retries reached (10s)
    throw new Error(`attach to ${pid} timed out`);
  }

  /**
   * dump and pack to ipa. if no name is provided, the bundle id and version will be used
   * @param {import("fs").PathLike?} suggested path of ipa
   * @returns {Promise<string>} final path of ipa
   */
  async pack(suggested) {
    const DIR_NAME = '.bagbak'; // do not use tmpdir here, because sometimes it might be in different partition
    const payload = join(DIR_NAME, this.bundle, 'Payload');
    await rm(payload, { recursive: true, force: true });
    await mkdir(payload, { recursive: true });
    await this.dump(payload, true, true);
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

    {
      // remove artifact
      const artifact = join(DIR_NAME, this.bundle);
      await rm(artifact, { recursive: true, force: true })
        .catch(error => {
          debug(`Warning: failed to remove artifact directory ${artifact}`, error);
        })
        .then(() => rmdir(DIR_NAME))
        .catch(_ => { /* ignore */ });
    }

    return ipa;
  }
}
