# AOW Reconstruction

Android game reconstruction research and independently implemented client/server project.

## Status
- Initial planning and APK inspection pending.
- Original user-provided APK: `aow.apk` (~256 MB), supplied in ChatGPT conversation; **not committed**.
- Engine, protocol, assets, server endpoints and feasibility are **not yet verified**.
- Goal: reproduce the original experience as closely as technically and legally possible; no unsupported 100% completion claim.

## Workflow
1. Inspect APK locally in an isolated environment with `aapt2`, `apkanalyzer`, `jadx`, `apktool`, `unzip` and native-library inspection.
2. Produce `docs/APK_ANALYSIS.md` with verified findings and confidence levels.
3. Document feature inventory and client/server boundary.
4. Implement an independently operated server and compatible client only for authorized use.
5. Add reproducible builds and automated tests; publish test APK as CI artifact only when functional.

## Security and rights
Do not commit original APK, extracted proprietary assets, private keys, account credentials, or personal data. Do not scan, exploit, intercept other users, or access the publisher's infrastructure without authorization. IP addresses discovered in application configuration do not grant server access or source code.

## Codex starting point
Read `AGENTS.md`, then complete the first issue. Make small branches and PRs with evidence and tests. Do not fabricate APK findings. Request original APK via a secure authorized handoff if not present in your working environment.
