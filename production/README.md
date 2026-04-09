# Production Release Folder

This folder centralizes the production-ready software handoff assets for this
project.

## Contents

- `PRODUCTION_CHECKLIST.md`: final release validation and sign-off list.
- `SECURITY_BASELINE.md`: minimum enforced production security requirements.
- `RELEASE_NOTES.md`: production build profile and known hardware integration gaps.

## Scope

This project now supports a strict production build mode via:

- CMake option: `-DFIRMWARE_PRODUCTION=ON`
- Compile definition: `FIRMWARE_PRODUCTION=1`

In production mode, the firmware:

- disables settings debug snapshot/restore interfaces,
- requires crypto engine sensitive operations to have:
  - master key set,
  - device secret set,
  - secure element binding established,
- keeps sensitive buffers zeroized on failure paths.

## Build commands (production)

```bash
cmake -S firmware -B firmware/build-prod -DFIRMWARE_PRODUCTION=ON
cmake --build firmware/build-prod
ctest --test-dir firmware/build-prod --output-on-failure
```

