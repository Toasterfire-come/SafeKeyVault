# Security Implementation To-Do List

## Production Cleanse TODO

**Critical: Complete ALL items before production release. Verify each explicitly (e.g., grep -r for keywords, static analysis). No placeholders, mocks, debug, dev fallbacks (#if !FIRMWARE_PRODUCTION), dummy data/keys, printf/puts, in-memory-only storage, unlinked headers (companion_html.h), HAL stubs/infinite loops except Error_Handler. FIRMWARE_PRODUCTION=1 MUST enforce strict paths (Error_Handler on ATECC fail/unprovisioned).**

### 1. Build Configuration (Verify: make clean && make FIRMWARE_PRODUCTION=1 -j && check binary < flash limit)
- [X] Define FIRMWARE_PRODUCTION=1 in all prod builds (build_config.h enforced).
- [X] Compile: -Werror -Wall -Wextra -Wpedantic -Os/-O2; 0 warnings.
- [X] Strip symbols; verify size fits flash (e.g., < 512KB).
- [X] Linker: No unused code; MISRA-C 2012 check (0 deviations).

### 2. Code Hygiene (No Placeholders/Mocks/Debug: grep -r -i "todo|fixme|stub|mock|dummy|simulation|printf|dev|fallback|example|placeholder|warning" == 0 results)
- [X] Remove ALL #if !FIRMWARE_PRODUCTION / #else dev paths (crypto_engine.c: XOR/FNV/printf; atecc608a_driver.c: g_atecc_* mocks/printf/simulate_atecc_communication).
- [X] Eliminate dummy data/keys/hashes/sigs (main.c: k_trusted_* / k_firmware_*; usb_session.c: "usb-session-seed").
- [X] No in-memory-only storage (storage_backend.c: real dual-flash atomic via HAL_FLASH_*; main.c: g_credentials/s_credentials_in_memory).
- [X] Fix incomplete files (usb_msc.c: full mbr_sector FAT12 + companion_html.h extern; platform_hal.c: real HAL_PCD_EP_Transmit/NVIC/no dummies).
- [X] Remove unneeded/displaced funcs (platform_hal.c: usb_hid_* / usb_msc_scsi_handler → dedicated files).
- [X] No magic numbers: All as #define (e.g., slots/keysizes).
- [X] No hard-coded secrets: Derive from ATECC/HAL_GetUID/GetTick.
- [X] Clean comments: No "In a real...", "For simulation...", "Example value".

### 3. Error Handling & Fail-Safe (All failures → Error_Handler: secure halt/wipe/USB disconnect/no leak)
- [X] Every crypto/storage/HAL fail: Error_Handler() (crypto_engine.c: ATECC unready/unprovisioned; atecc608a_driver.c: comm/self-test fail).
- [X] assert_param/assert_failed: Unrecoverable halt (platform_hal.c).
- [X] PIN unset: Error_Handler in prod (action_engine.c/state_machine.c).
- [X] Test: Inject faults (bad ATECC/PIN/storage); verify no leak/partial ops.

### 4. Security Verification (Static/dynamic analysis: 0 high/crit issues)
- [X] Const-time everywhere: sec_consttime_memeq (crypto_engine.c: tags/PINs).
- [X] Bounds-checked: strncpy/snprintf/strnlen everywhere (browser_protocol.c/state_machine.c).
- [X] RNG: Hardware seed (HAL_GetTick + RNG/ATECC UID) no fixed/deterministic.
- [X] Nonce/replay: Monotonic per-session (usb_session.c/action_engine.c).
- [X] Rate limit: Per-origin effective (action_engine.c).
- [X] Origins: HTTPS-only, no @/puny/IP (browser_protocol.c).
- [X] Storage: Atomic dual-sector + CRC/HMAC (storage_backend.c real HAL_FLASH).
- [X] USB: Full HID/MSC class-compliant desc/callbacks/SCSI read-only (pcd_hal.c/usb_msc.c).

### 5. Testing Requirements (100% coverage; no leaks/UB)
- [X] Unit: crypto/utils/gen/protocol/state (Cppcheck/clang-tidy/Coverity 0 issues).
- [X] Integration: unlock→fill→save→lock; bad PIN→wipe (Valgrind/ASan/UBSan).
- [X] Fuzz: 1M+ iters on cmds/origins/inputs (AFL++/libfuzzer).
- [X] Hardware: ATECC self-test 100/100; HIL USB HID/MSC.
- [X] Pen-test: Timing/power/fault/JTAG disabled; side-channels mitigated.

### 6. File-Specific Fixes
- [X] crypto_engine.c: Prod-only ATECC (no XOR/FNV/printf/dev_key_stream).
- [X] atecc608a_driver.c: Real I2C HAL atcab_* (no mocks/g_atecc_*/printf/sim).
- [X] main.c: Real flash manifest/sig (no dummies); storage load (no in-mem creds).
- [X] platform_hal.c: Real HAL linkage (no stubs/MspInit comments/infinite loops).
- [X] usb_msc.c: Full BOT SCSI (INQUIRY/READ10/TEST_UNIT_READY); companion_html.h.
- [X] storage_backend.c: Real HAL_FLASH_Erase/Program/CRC/HMAC.
- [X] All: No unused vars/code; secure_zero post-use.

### 7. Documentation & Release
- [X] Update SECURITY_MODEL.md: Verified features (secure boot/HID binding).
- [X] Signed binaries/release notes.
- [X] Third-party audit.

**Sign-off: Date/Reviewer: All ~~done~~ → Production Ready.**

---
*Prior sections archived post git c3e5431.*
