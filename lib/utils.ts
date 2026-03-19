import { readFile, stat } from "fs/promises";
import { type PathLike } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export const directoryExists = (path: PathLike): Promise<boolean> =>
  stat(path)
    .then((info) => info.isDirectory())
    .catch(() => false);

export function readFromPackage(...components: string[]): Promise<string> {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  const agent = join(__dirname, "..", ...components);
  return readFile(agent, "utf8");
}

export async function version(): Promise<string> {
  const { version } = JSON.parse(await readFromPackage("package.json"));
  return version;
}

let __debug = "DEBUG" in process.env;

export function debug(...args: unknown[]) {
  if (__debug) console.log(...args);
}

export function enableDebug(value?: boolean): boolean {
  if (value !== undefined) __debug = value;
  return __debug;
}
