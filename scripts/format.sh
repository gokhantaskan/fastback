#!/usr/bin/env bash

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

PRETTIER_ARGS=(
  "${ROOT_DIR}/**/*.{md,mdx,yml,yaml,toml,json,css}"
  --config "${ROOT_DIR}/.prettierrc"
  --ignore-path "${ROOT_DIR}/.gitignore"
  -u
)

echo "Checking formatting..."
if npx --yes prettier --check "${PRETTIER_ARGS[@]}"; then
  exit 0
fi

echo
read -p "Apply formatting changes? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  npx --yes prettier --write "${PRETTIER_ARGS[@]}" -l
fi