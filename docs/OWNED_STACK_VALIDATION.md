# Owned-stack validation prerequisites

`make validate` remains full discovery: no skips, expected failures, import failures or missing tests are accepted. A checkout containing `sdk/liminal_agent_control` additionally needs Linux/POSIX, a reachable Docker daemon, the pinned signing dependency, immutable worker and observer images, and a fresh real G03 receiver capture.

The required governance workflow runs for PRs targeting `main` and stacked `agent/**` branches, including `agent/effect-dispatch-gate-20261013`. Push validation remains enabled for `main`; a stacked G03 PR does not need a temporary retarget to trigger the full gate.

The workflow calls `scripts/prepare_owned_stack_validation.py` before the unchanged full gate. The helper:

1. Requires a clean source checkout and a fresh output directory outside it.
2. Creates a separate virtual environment and installs `experiments/agent_control/observer-requirements.txt`.
3. Resolves the worker's pinned digest to its immutable image ID, builds the observer from its pinned base and dependency, and exports all four required image bindings.
4. Runs the actual G03 runtime in a separate process, preserves its bytes in read-only `evidence/receiver-preparation.json`, and records their SHA256 in `preparation.json`. It independently verifies this snapshot against the checked-out revision and recorded hash, requires all nine capture mutation tests, and executes those nine against the snapshot with the strict runner.
5. Exports the prepared environment and interpreter for a fresh `make validate` process.

`READY_FOR_VALIDATION` reports only successful preparation. The subsequent full gate must pass; unavailable Docker, failed installation, invalid image identity, missing capture or missing tests fail preparation. There is no fake Docker mode or skip allowance. Without the owned SDK, preparation reports `NOT_APPLICABLE` and the existing full gate runs unchanged.

Full discovery writes a new runtime capture to `evidence/receiver.json`; it does not overwrite the preparation snapshot or `receiver-preparation-verification.json`. After `make validate`, the owned-stack gate independently verifies this final capture into `receiver-final-verification.json`, then checks that all nine capture tests exist and runs them in fresh processes against the final capture. These mandatory postchecks fail the gate on missing, invalid or incomplete evidence. Each verifier result records the SHA256 of the bytes it actually checked, so preparation and final verification cannot be mistaken for the same runtime capture.

The helper accepts `--output-directory`. In GitHub Actions it writes the prepared variables and interpreter to `GITHUB_ENV` and `GITHUB_PATH`; explicit paths can be supplied with `--github-env` and `--github-path`. `preparation.json` and the public evidence reports are uploaded separately from the virtual environment. The recorded source SHA identifies the actual checkout, including a PR merge checkout when that is the validation subject.

Core and kernel PR workflows also cover `main` and `agent/**`, subject to their existing path filters. Compiler, sanitizer and kernel jobs declare a narrower scope only when the owned SDK is present: every C suite plus both production CLI characterization modules, including their runtime/controller contracts. Their original full-test behavior remains when the SDK is absent. The required governance gate retains every discovered Python test; dedicated G03, G02, command, observer and Docker jobs retain their separate runtime evidence.

Local helper regressions check failure boundaries and test completeness with explicit synthetic fixtures. They do not establish Docker execution. A local check that omits real preparation and the full owned-stack gate must report them as **NOT_RUN**, not PASS. Invoking preparation without a reachable daemon exits unsuccessfully; CI must establish the full result at the published revision.
