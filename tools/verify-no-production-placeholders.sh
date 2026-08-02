#!/usr/bin/env bash
set -euo pipefail

# High-confidence executable placeholder constructs. Documentation, fixtures, generated bindings,
# demo adapters, and test doubles are intentionally outside this production-source gate.
tracked_sources=()
while IFS= read -r path; do
  case "$path" in
    */tests/*|*/test/*|*/fuzz/*|*/Generated/*|*/uniffi/*|*/demo.rs|*/DemoAdapters.swift|*/InMemory.swift)
      continue
      ;;
    *.rs|*.swift|*.kt|*.kts|*.ts|*.tsx|*.js|*.sh)
      tracked_sources+=("$path")
      ;;
  esac
done < <(git ls-files)

if ((${#tracked_sources[@]} == 0)); then
  echo "no tracked production sources found" >&2
  exit 1
fi

pattern='todo![(]|unimplemented![(]|IMPLEMENT[[:space:]_-]*ME|NOT[[:space:]_-]*IMPLEMENTED|PLACEHOLDER[[:space:]_-]*IMPLEMENTATION'
if git grep -nEI "$pattern" -- "${tracked_sources[@]}"; then
  echo "production placeholder construct detected" >&2
  exit 1
fi

echo "production placeholder audit passed (${#tracked_sources[@]} tracked source files)"
