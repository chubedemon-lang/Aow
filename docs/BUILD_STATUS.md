# Android build status

Updated: 2026-11-04

**No Android client project is present in this repository. No APK has been built or verified.**

Current tree contains documentation and a read-only APK ZIP inventory utility. The CI workflow runs synthetic Python tests only; it does not build an APK.

## Evidence required before claiming an APK is ready

1. Commit an authorized Android/Unity project with reproducible build configuration.
2. Add an Android build job that uploads a named APK artifact only on successful build.
3. Confirm the workflow run succeeded and that its artifact listing includes the APK.
4. Optionally download the artifact, verify ZIP signature, size, SHA-256 and Android manifest/package metadata.
5. Report the exact workflow URL, artifact name and checksum.

No proprietary original APK, extracted asset bundles, or credentials should be uploaded to this public repository.

## Immediate next steps

- Obtain authorized local access to APK bytes for manifest/asset inventory; do not claim new observations without access.
- Establish licensing/rights for reused assets and engine choice.
- Implement a clean-room interactive prototype and test it before adding Android packaging.
