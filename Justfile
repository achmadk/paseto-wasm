set dotenv-load
set export

NO_HEADLESS := "true"

test:
  wasm-pack test --chrome