// Vite `?raw` imports — content inlined as a string at bundle time.
// Used by `embed-assets-roundtrip.test.ts` to read source files in the
// Workers test runtime without `node:fs`.

declare module "*?raw" {
  const content: string;
  export default content;
}
