/**
 *
 * @param {import('fs').PathLike} root
 * @returns {Promise<Map<import('fs').PathLike, [import('fs').PathLike, import('./macho.js').MachO][]>>}
 */
export function findEncryptedBinaries(root: import('fs').PathLike): Promise<Map<import('fs').PathLike, [import('fs').PathLike, import('./macho.js').MachO][]>>;
export class AppBundleVisitor {
    /**
     * root of the app bundle
     * @param {import('fs').PathLike} root
     */
    constructor(root: import('fs').PathLike);
    /**
     * @returns {AsyncGenerator<[string, string, import('./macho.js').MachO]>}
     */
    visitRoot(): AsyncGenerator<[string, string, import('./macho.js').MachO]>;
    /**
     *
     * @returns {Promise<Map<import('fs').PathLike, [import('fs').PathLike, import('./macho.js').MachO][]>>}
     */
    encryptedBinaries(): Promise<Map<import('fs').PathLike, [import('fs').PathLike, import('./macho.js').MachO][]>>;
    #private;
}
