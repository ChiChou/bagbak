import { readFile, stat } from "fs/promises";
import { type PathLike } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

import pkg from "../package.json" with { type: "json" };

export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export const directoryExists = (path: PathLike): Promise<boolean> =>
  stat(path)
    .then((info) => info.isDirectory())
    .catch(() => false);

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(
  __dirname,
  process.env.TSDOWN_BUILD ? join("..", "..") : "..",
);

export function readFromPackage(...components: string[]): Promise<string> {
  return readFile(join(packageRoot, ...components), "utf8");
}

export function version(): string {
  return pkg.version;
}

let __debug = "DEBUG" in process.env;

export function debug(...args: unknown[]) {
  if (__debug) console.log(...args);
}

export function enableDebug(value?: boolean): boolean {
  if (value !== undefined) __debug = value;
  return __debug;
}
