import { EventEmitter } from "events";
import { mkdir } from "fs/promises";
import { tmpdir } from "os";
import { basename, join, relative } from "path";

import { Device } from "frida";

import { apps } from './lib/installation.js';
import { Pull } from './lib/scp.js';
import { connect } from './lib/ssh.js';
import { directoryExists } from './lib/utils.js';
import { findEncryptedBinaries } from "./lib/scan.js";

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

  /**
   * 
   * @param {boolean} coldBoot whether to kill existing instance
   * @returns {Promise<import("frida").Session>} frida session
   */
  async run(coldBoot) {
    const app = this.app;

    let needsNew = true;

    if (app.parameters.started) {
      if (coldBoot || !app.parameters.frontmost) {
        await this.#device.kill(app.pid);
      } else {
        needsNew = false;
      }
    }

    if (needsNew) {
      const pid = await this.#device.spawn(app.identifier);
      const session = await this.#device.attach(pid);
      // await this.#device.resume(pid);
      // await sleep(1000);
      return session;
    }

    return this.#device.attach(app.pid);
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
    console.log('copy to', parent);
    console.log(this.app.parameters.path);

    const rootBundle = join(parent, basename(this.app.parameters.path));
    if (!await directoryExists(rootBundle)) {
      await this.copyToLocal(this.app.parameters.path, parent);
    }

    const map = await findEncryptedBinaries(rootBundle);
    for (const [scope, list] of map.entries()) {
      console.log('scope', scope);
      for (const item of list) {
        console.log(item)
      }
    }

    // todo: dump
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