import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";
import {nodePolyfills} from 'vite-plugin-node-polyfills';

export default defineConfig({
  plugins: [
    nodePolyfills({
      protocolImports: true,
    }),
    wasm(),
  ],
  build: {
    target: "esnext",
  },
});
