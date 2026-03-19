import { Application, Device } from "frida";
import { PathLike } from "fs";
import { EventEmitter } from "events";

export class BagBak extends EventEmitter {
    constructor(device: Device, app: Application);
    get bundle(): string;
    get remote(): string;

    /**
     * dump and pack to ipa. if no name is provided, the bundle id and version will be used
     */
    pack(suggested?: PathLike): Promise<string>;

    on(event: 'status', listener: (message: string) => void): this;
    on(event: 'patch', listener: (name: string) => void): this;
    on(event: 'streaming', listener: (totalSize: number) => void): this;
}
