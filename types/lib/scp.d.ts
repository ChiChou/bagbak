/**
 * @param {string} name
 * @returns {string} escaped filename
 */
export function quote(name: string): string;
export class Pull extends EventEmitter {
    /**
     *
     * @param {Client} client
     * @param {PathLike} remote
     * @param {PathLike} local
     * @param {boolean} recursive
     */
    constructor(client: Client, remote: PathLike, local?: PathLike, recursive?: boolean);
    /**
     * @public
     * @type {SCPReceiver}
     */
    public receiver: SCPReceiver;
    /**
     * @returns {Promise<void>}
     */
    execute(): Promise<void>;
    #private;
}
import { EventEmitter } from "events";
declare class SCPReceiver extends Duplex {
    /**
     *
     * @param {string} dest
     * @param {boolean} recursive
     */
    constructor(dest: string, recursive: boolean);
    /**
     * @type {WriteStream | null}
     * @private
     */
    private output;
    /**
     * @type {Date | null}
     * @private
     */
    private mtime;
    /**
     * @type {Date | null}
     * @private
     */
    private atime;
    _read(): void;
    /**
     *
     * @param {Buffer} chunk
     * @param {BufferEncoding} encoding
     * @param {function} callback
     */
    _write(chunk: Buffer, encoding: BufferEncoding, callback: Function): any;
    #private;
}
import { Duplex } from "stream";
export {};
