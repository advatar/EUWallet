```md
# AGENTS

## Working Rules

- Always `git add` and commit and push after creating or editing files. Use clear, descriptive commit messages.
- Verify builds locally before claiming completion for any change.
- After assessing a request, add or update related tasks in `STATUS.md` before implementation. Also, create a github issue with all the details and the plan.
- THIS IS IMPORTANT: Keep going without pausing for confirmation if you already know what the next step is; only ask when a decision is blocking progress.
- Never stage, commit, or alter files you did not edit for the task; leave unrelated changes for their owner.
- Merge a feature into `main` promptly once it is working and verified; do not let completed work drift on long-lived branches.
- Other agents may be working in the same repo; mind your own business and avoid unrelated investigation or edits.
- When you have unchecked tasks, complete them one by one after passing tests, do not stop
- When adding new functionality add unit tests
- Whenever Rust/UniFFI APIs change, regenerate `ios/Generated/wallet_core.swift`,
  `ios/Generated/wallet_coreFFI.h`, and the local `ios/WalletCore.xcframework`
  with `ios/build-rust-xcframework.sh` before building Xcode; run
  `ios/verify-rust-xcframework.sh` and commit the tracked generated bindings.
