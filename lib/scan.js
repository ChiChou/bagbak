import { stat, readdir } from 'fs/promises';
import path from 'path';

import { directoryExists } from './utils.js';
import { parse as parseMachO, MH_EXECUTE } from './macho.js';

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
    if (!await directoryExists(pluginsDir)) return;
    for (const item of await readdir(pluginsDir)) {
      if (item.endsWith('.appex')) {
        const fullname = path.join(pluginsDir, item);
        const scope = path.relative(this.#root, fullname);
        yield* this.#visit(scope, fullname);
      }
    }
  }

  async *visitRoot() {
    for (const item of await readdir(this.#root)) {
      const fullname = path.join(this.#root, item);
      const info = await stat(fullname);

      if (info.isFile()) {
        yield* this.#visitFile('.', fullname);
      } else if (info.isDirectory()) {
        if (item === 'PlugIns') {
          yield* this.#visitPlugins(fullname);
        } else {
          yield* this.#visit('.', fullname);
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
      if (info.encryptInfo) {
        yield [scope, item, info];
      }
    } catch (_) {

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

  async encryptedBinaries() {
    const buckets = new Map();
    for await (const [scope, file, info] of this.visitRoot()) {
      const adjustedFile = path.relative(this.#root, file);
      const { encryptInfo } = info;

      const bucket = buckets.get(scope) ?? [];
      bucket.push([adjustedFile, encryptInfo]);
      buckets.set(scope, bucket);
    }

    return buckets;
  }
}

/**
 * 
 * @param {import('fs').PathLike} root 
 * @returns {Promise<Map<import('fs').PathLike, [import('fs').PathLike, import('./lib/macho.js').MachOInfo][]>>}
 */
export function findEncryptedBinaries(root) {
  const visitor = new AppBundleVisitor(root);
  return visitor.encryptedBinaries();
}
