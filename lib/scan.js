import { readFile, readdir, stat, rm } from 'fs/promises';
import path from 'path';

import { parse as parseMachO, InvalidMachOError, NotMachOError } from './macho.js';
import { parse as parsePlist } from './plist.js';
import { debug } from './utils.js';

/**
 * hack: fix Windows path separator
 * @param {string} p
 * @returns {string}
 */
const fix = (() => {
  if (path.sep !== '/') {

    /**
     * @param {string} p
     * @returns {string}
     */
    return (p) => p.replaceAll(path.sep, '/');
  }

  /**
   * @param {string} p
   * @returns {string}
   */
  return (p) => p;
})();

const exclude = {
  dirs: new Set(['SC_Info', '_CodeSignature']),
  files: new Set(['iTunesMetadata.plist', 'embedded.mobileprovision'])
};

export class AppBundleVisitor {
  #root;

  /**
   * root of the app bundle
   * @param {import('fs').PathLike} root 
   */
  constructor(root) {
    this.#root = root;
  }

  /**
   * 
   * @param {import('fs').PathLike} pluginsDir 
   */
  async *#visitPlugins(pluginsDir) {
    for (const item of await readdir(pluginsDir)) {
      if (item.endsWith('.appex')) {
        const fullname = path.join(pluginsDir, item);
        const scope = fullname;
        yield* this.#visit(scope, fullname);
      }
    }
  }

  /**
   * @returns {AsyncGenerator<[string, string, import('./macho.js').MachO]>}
   */
  async *visitRoot() {
    for (const item of await readdir(this.#root)) {
      const fullname = path.join(this.#root, item);
      const info = await stat(fullname);

      if (info.isFile()) {
        yield* this.#visitFile(this.#root, fullname);
      } else if (info.isDirectory()) {
        if (item === 'PlugIns' || item === 'Extensions') {
          yield* this.#visitPlugins(fullname);
        } else {
          yield* this.#visit(this.#root, fullname);
        }
      }
    }
  }

  /**
   * 
   * @param {import('fs').PathLike} belongs 
   * @param {import('fs').PathLike} item 
   */
  async *#visitFile(scope, item) {
    try {
      const info = await parseMachO(item);
      debug('mach-o info', item, info);
      if (info.encryptInfo) {
        yield [scope, item, info];
      }
    } catch (err) {
      if (err instanceof NotMachOError) {
        return;
      } else if (err instanceof InvalidMachOError) {
        console.error('invalid mach-o', item, err.message);
      } else {
        throw err;
      }
    }
  }

  /**
   * 
   * @param {import('fs').PathLike} scope the bundle that contains the item
   * @param {import('fs').PathLike} item 
   */
  async * #visit(scope, item) {
    const info = await stat(item);
    if (info.isDirectory()) {
      const files = await readdir(item);
      for (const file of files) {
        yield* this.#visit(scope, path.join(item, file));
      }
    } else if (info.isFile()) {
      yield* this.#visitFile(scope, item);
    }
  }

  /**
   * @returns {Promise<Map<import('fs').PathLike, [import('fs').PathLike, import('./macho.js').MachO][]>>}
   */
  async encryptedBinaries() {
    /**
     * @type {Map<import('fs').PathLike, [import('fs').PathLike, import('./macho.js').MachO][]>}
     */
    const buckets = new Map();
    for await (const [scope, file, info] of this.visitRoot()) {
      const adjustedFile = path.relative(this.#root, file);
      const bucket = buckets.get(scope) ?? [];
      bucket.push([fix(adjustedFile), info]);
      buckets.set(scope, bucket);
    }

    /**
     * @type {Map<import('fs').PathLike, [import('fs').PathLike, import('./macho.js').MachO][]>}
     */
    const result = new Map();
    for (const [scope, encryptedFiles] of buckets.entries()) {
      const adjustedScope = path.relative(this.#root, scope);

      const infoPlist = path.join(scope, 'Info.plist');
      const plist = parsePlist(await readFile(infoPlist));
      const mainExecutable = fix(path.join(adjustedScope, plist['CFBundleExecutable']));
      result.set(mainExecutable, encryptedFiles);
    }

    return result;
  }

  /**
   * @returns {Promise<void>}
   */
  async removeUnwanted() {
    /**
     * @param {PathLike} dir
     * @returns {Promise<void>}
     */
    async function visit(dir) {
      for (const item of await readdir(dir)) {
        const fullname = path.join(dir, item);
        const info = await stat(fullname);
        if (!info.isDirectory()) {
          continue;
        }

        if (exclude.dirs.has(item)) {
          await rm(fullname, { recursive: true, force: true }).catch(() => { });
        } else {
          await visit(fullname);
        }
      }
    }

    for (const name of exclude.files) {
      await rm(path.join(this.#root, name), { force: true }).catch(() => { });
    }

    return visit(this.#root);
  }
}
