import { readdir, stat, rm } from 'fs/promises';
import path from 'path';

import { parse as parseMachO, InvalidMachOError, NotMachOError } from './macho.js';


const exclude = {
  dirs: new Set(['SC_Info', '_CodeSignature']),
  files: new Set(['iTunesMetadata.plist', 'embedded.mobileprovision'])
};

/**
 * @typedef EncryptedBinaryInfo
 * @property {[import('fs').PathLike, import('./macho.js').MachO][]} dylibs
 * @property {import('fs').PathLike} executable
*/

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
   * @returns {AsyncGenerator<[import('fs').PathLike, import('./macho.js').MachO]>}
   */
  async *visitRoot() {
    for (const item of await readdir(this.#root)) {
      const fullname = path.join(this.#root, item);
      const info = await stat(fullname);

      if (info.isFile()) {
        yield* this.#visitFile(fullname);
      } else if (info.isDirectory()) {
        yield* this.#visit(fullname);
      }
    }
  }

  /**
   * 
   * @param {import('fs').PathLike} item 
   * @returns {AsyncGenerator<[import('fs').PathLike, import('./macho.js').MachO]>}
   */
  async *#visitFile(item) {
    try {
      const info = await parseMachO(item);
      if (info.encryptInfo.id !== 0) {
        const relative = path.relative(this.#root, item);
        yield [relative, info];
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
   * @param {import('fs').PathLike} item 
   * @returns {AsyncGenerator<[import('fs').PathLike, import('./macho.js').MachO]>}
   */
  async * #visit(item) {
    const info = await stat(item);
    if (info.isDirectory()) {
      const files = await readdir(item);
      for (const file of files) {
        yield* this.#visit(path.join(item, file));
      }
    } else if (info.isFile()) {
      yield* this.#visitFile(item);
    }
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
