import { readFile, stat } from 'fs/promises';

import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

/**
 * to sleep
 * @param {number} ms 
 * @returns {Promise<void>} 
 */
export const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * 
 * @param {import('fs').PathLike} path directory to check
 * @returns {Promise<boolean>}
 */
export const directoryExists = path => stat(path)
  .then(info => info.isDirectory())
  .catch(() => false);


/**
 * read source code of agent
 * @param  {...string} components
 * @returns {Promise<string>}
 */
export function readFromPackage(...components) {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  const agent = join(__dirname, '..', ...components);
  return readFile(agent, 'utf8');
}


/**
 * read version from package.json
 * @returns {Promise<string>}
 */
export async function version() {
  const { version } = JSON.parse(await readFromPackage('package.json'));
  return version;
}


let __debug = 'DEBUG' in process.env;

/**
 * debug log
 * @param  {...any} args
 */
export function debug() {
  if (__debug)
    console.log(...arguments);
}

/**
 * @param {boolean} value set new value
 * @returns {boolean}
 */
export function enableDebug(value=undefined) {
  if (value !== undefined) __debug = value;
  return __debug;
}
