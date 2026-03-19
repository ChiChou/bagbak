import ObjC from "frida-objc-bridge";

export interface EncryptInfo {
  offset: number;
  size: number;
  id: number;
}

export interface MachOInfo {
  type: number;
  encrypt: EncryptInfo;
  offset: number; // offset of LC_ENCRYPTION_INFO_64 command
}

export interface ExtensionInfo {
  id: string;
  path: string;
  exec: string;
  abs: string;
}

export type MachOTasks = Record<string, MachOInfo>;

type NativeAPI = {
  open: NativeFunction<number, [NativePointerValue, number]>;
  close: NativeFunction<number, [number]>;
  read: NativeFunction<number, [number, NativePointerValue, number]>;
  pwrite: NativeFunction<number, [number, NativePointerValue, number, number]>;
  exit: NativeFunction<void, [number]>;
};

let api: NativeAPI | null = null;

export function nsError<T>(fn: (pError: NativePointer) => T): T {
  const pError = Memory.alloc(Process.pointerSize);
  pError.writePointer(NULL);
  const result = fn(pError);
  const err = pError.readPointer();
  if (!err.isNull()) throw new Error(new ObjC.Object(err).toString());
  return result;
}

export function getApi(): NativeAPI {
  if (api) return api;

  api = {
    open: new NativeFunction(Module.getGlobalExportByName("open"), "int", [
      "pointer",
      "int",
    ]),
    close: new NativeFunction(Module.getGlobalExportByName("close"), "int", [
      "int",
    ]),
    read: new NativeFunction(Module.getGlobalExportByName("read"), "long", [
      "int",
      "pointer",
      "long",
    ]),
    pwrite: new NativeFunction(Module.getGlobalExportByName("pwrite"), "long", [
      "int",
      "pointer",
      "long",
      "long",
    ]),
    exit: new NativeFunction(Module.getGlobalExportByName("exit"), "void", [
      "int",
    ]),
  };

  return api;
}
