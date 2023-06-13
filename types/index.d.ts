import { Application, Device } from "frida";
import { PathLike } from "fs";

export class BagBak extends EventEmitter {
    constructor(device: Device, app: Application);
    get bundle(): string;
    get remote(): string;

    /**
     * dump raw app bundle to directory (no ipa)
     */
    dump(parent: PathLike, override?: boolean): Promise<string>;

    /**
     * dump and pack to ipa. if no name is provided, the bundle id and version will be used
     */
    pack(suggested?: PathLike): Promise<string>;

    on(event: 'download', listener: (src: string, size: number) => void): this;
    on(event: 'mkdir', listener: (path: string) => void): this;
    on(event: 'progress', listener: (src: string, written: number, size: number) => void): this;
    on(event: 'done', listener: (src: string) => void): this;
    on(event: 'sshBegin', listener: () => void): this;
    on(event: 'sshFinish', listener: () => void): this;
    on(event: 'patch', listener: (remote: string) => void): this;
}
