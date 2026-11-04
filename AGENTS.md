# Codex instructions — AOW

1. Start with Issue #1: inspect `aow.apk` only after it is available in an authorized workspace. Report SHA256, manifest, engine evidence, native libraries, assets, and configuration in `docs/APK_ANALYSIS.md`.
2. Never fabricate APK findings, server endpoints, protocol behavior or test results.
3. Build an independent server; do not access, exploit or interfere with official game infrastructure.
4. Use clean-room implementations and only assets the project is authorized to use. Never commit original APK, proprietary extracted files, credentials, tokens or personal information.
5. Maintain a feature matrix with evidence and tests. Implement a playable vertical slice, then expand incrementally.
6. Make small branches and PRs; include test commands and actual results. CI should produce an APK artifact only when a real Android project exists.
