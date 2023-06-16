/**
 *
 * @param {PathLike} file
 * @return {Promise<MachO>}
 */
export function parse(file: PathLike): Promise<MachO>;
/**
 * @typedef MachO
 *
 * @property {string} path
 * @property {number} type
 * @property {EncryptInfo} encryptInfo
 * @property {number} encCmdOffset
 */
/**
 * @typedef EncryptInfo
 *
 * @property {number} offset
 * @property {number} size
 * @property {number} id
 */
export class NotMachOError extends Error {
    /**
     *
     * @param {import('fs').PathLike} path
     */
    constructor(path: import('fs').PathLike);
}
export class InvalidMachOError extends Error {
    constructor(message: any);
}
export const MH_EXECUTE: 2;
export const MH_DYLIB: 6;
export const MH_DYLINKER: 7;
export const MH_BUNDLE: 8;
export type MachO = {
    path: string;
    type: number;
    encryptInfo: EncryptInfo;
    encCmdOffset: number;
};
export type EncryptInfo = {
    offset: number;
    size: number;
    id: number;
};
