/**
 * @typedef MessagePayload
 * @property {string} event
 */
/**
 * main class
 */
export class BagBak extends EventEmitter {
    /**
     * constructor
     * @param {import("frida").Device} device
     * @param {import("frida").Application} app
     */
    constructor(device: import("frida").Device, app: import("frida").Application);
    get bundle(): string;
    get remote(): string;
    /**
     * dump raw app bundle to directory (no ipa)
     * @param {import("fs").PathLike} parent path
     * @param {boolean} override whether to override existing files
     * @returns {Promise<string>}
     */
    dump(parent: import("fs").PathLike, override?: boolean): Promise<string>;
    /**
     * dump and pack to ipa. if no name is provided, the bundle id and version will be used
     * @param {import("fs").PathLike?} suggested path of ipa
     * @returns {Promise<string>} final path of ipa
     */
    pack(suggested: import("fs").PathLike | null): Promise<string>;
    #private;
}
export type MessagePayload = {
    event: string;
};
import { EventEmitter } from "events";
