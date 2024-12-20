import init, { greet } from "../rust-proj/pkg/rust_proj";

async function main() {
  await init();

  console.log(greet("TypeScript"));
}

main().catch(console.error);
