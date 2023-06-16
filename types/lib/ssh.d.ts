/**
 *
 * @param {import("frida").Device} device
 * @returns {Promise<number>}
 */
export function scan(device: import("frida").Device): Promise<number>;
/**
 *
 * @param {import("frida").Device} device
 * @param {string} user
 * @param {string} password
 * @returns {Promise<Client>}
 */
export function connect(device: import("frida").Device, user?: string, password?: string): Promise<Client>;
/**
 *
 * @param {Client} client
 * @param {string} [initialCommand]
 * @returns {Promise<void>}
 */
export function interactive(client: Client, initialCommand?: string): Promise<void>;
