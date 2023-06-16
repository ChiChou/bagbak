/**
 *
 * @param {import("frida").Device} device
 * @returns {Promise<import('frida').Application[]>}
 */
export function enumerateApps(device: import("frida").Device): Promise<import('frida').Application[]>;
/**
 * read source code of agent
 * @param  {...string} components
 * @returns {Promise<string>}
 */
export function readFromPackage(...components: string[]): Promise<string>;
/**
 * read version from package.json
 * @returns {Promise<string>}
 */
export function version(): Promise<string>;
/**
 * debug log
 * @param  {...any} args
 */
export function debug(...args: any[]): void;
/**
 * @param {boolean} value set new value
 * @returns {boolean}
 */
export function enableDebug(value?: boolean): boolean;
export function sleep(ms: number): Promise<void>;
export function directoryExists(path: import('fs').PathLike): Promise<boolean>;
