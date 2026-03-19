import { defineConfig } from "tsdown";

export default defineConfig({
  entry: ["index.ts", "bin/bagbak.ts"],
  format: "esm",
  dts: true,
  outDir: "dist",
  unbundle: true,
});
