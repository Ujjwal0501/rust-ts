import init, { greet } from "rust-proj";

async function main() {
  await init();

  console.log(greet("TypeScript"));
}

main().catch(console.error);
