# Looper

Looper exists to run one `codex exec` instance repeatedly with the same prompt.

- It is intentionally "first turn only": each run kills old `codex exec` processes and starts a fresh one.
- Any longer-lived scaffolding/state should live in a TODO file in your target repo, and your prompt should point Codex at that file.

Example prompt shape:

```text
Work from crates/vcad-topology/docs/phase5-geometric-topology-consistency.md.
Pick the next incomplete item, implement and verify it, then update the todo (it's also good to document any failed attempts).
When you are done:
- commit your changes, then
- modify scripts/run-codex-task.message.txt with a one sentence summary, then
- call scripts/run-codex-task.sh
```

You'll need to manually add run-codex-task.sh to your `~/.codex/rules/default.rules` or just run it manually first in the ui and approve.

## Minimal Codex Checkout/Build

To update codex so it has most recent models:

```bash
cd /home/bepis/Documents/looper
git clone https://github.com/openai/codex.git codex
cd codex/codex-rs
cargo build --release
```

Looper will auto-detect `./codex/codex-rs/target/release/codex` (or set `CODEX_EXEC_BINARY`).
