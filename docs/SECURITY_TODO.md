# Security Implementation To-Do List

This document outlines key security features identified in `docs/SECURITY_MODEL.md` that require further implementation or verification in the firmware code. Each item represents a concrete task to enhance the device's security posture.

## ATECC608A Driver Implementation (High Priority)

1.  **Implement `atecc608a_driver.c` for core ATECC functions:**
    *   ~~Replace placeholder / stub implementations of `atecc608a_init()`.~~ (Done - `firmware/src/atecc608a_driver.c`)
    *   ~~Implement `atecc608a_self_test()` to verify hardware functionality.~~ (Done - `firmware/src/atecc608a_driver.c`)
    *   ~~Implement `atecc608a_is_slot_provisioned()` for key status checks.~~ (Done - `firmware/src/atecc608a_driver.c`)
    *   ~~Implement `atecc608a_write_slot()` for secure key/data storage.~~ (Done - `firmware/src/atecc608a_driver.c`)
    *   ~~Implement `atecc608a_read_slot()` for secure data retrieval.~~ (Done - `firmware/src/atecc608a_driver.c`)
    *   ~~Implement `atecc608a_bind_slot()` (if applicable for specific usage).~~ (Done - `firmware/src/atecc608a_driver.c`)

2.  **Implement ATECC608A cryptographic primitives:** *(Next Phase)*
    *   Replace placeholder `atecc608a_sha256()` with the hardware-accelerated SHA256.
    *   Implement `atecc608a_encrypt_aead()` for hardware-backed authenticated encryption.
    *   Implement `atecc608a_decrypt_aead()` for hardware-backed authenticated decryption.
    *   Implement `atecc608a_derive_key_slot()` for hardware-backed key derivation (KDF).
    *   Implement `atecc608a_generate_ec_keypair()` for hardware-backed ECC key generation.
    *   Implement `atecc608a_ecdsa_sign()` for hardware-backed ECDSA signing.
    *   Implement `atecc608a_ecdsa_verify()` for hardware-backed ECDSA verification.

3.  **Refine `crypto_engine` production checks:** *(Later Phase)*
    *   Review all `Error_Handler()` calls under `FIRMWARE_PRODUCTION` to ensure they lead to a secure, unrecoverable state (e.g., system reset, lockout, or fault indicator).
    *   Ensure `atecc608a_is_available()` and `atecc608a_is_ready()` (if implemented) correctly query the ATECC state regarding interface readiness.

## Secure Boot and Signed Update Flow (Requires additional files)

1.  **Integrate `crypto_engine_ecdsa_verify` into a bootloader.**
    *   Develop or integrate a bootloader that verifies firmware authenticity using `crypto_engine_ecdsa_verify` against a trusted public key stored securely (e.g., in ATECC).
2.  **Implement a secure update mechanism.**
    *   Develop a mechanism to securely download, verify (using `crypto_engine_ecdsa_verify`), and install firmware updates.

## Authenticated HID Session/Channel Binding (Requires additional files)

1.  **Design and implement a secure channel protocol.**
    *   Utilize ATECC features (e.g., key agreement, secure messaging) to establish an authenticated, encrypted channel over HID.
    *   Integrate this channel into the browser protocol communication to prevent MITM attacks.

## Policy Enforcement (Requires additional files/review)

1.  **Review and verify logic for physical touch/hold confirmation.**
    *   Ensure all sensitive actions genuinely require physical interaction.
2.  **Verify PIN lockout and wipe state transitions.**
    *   Confirm these mechanisms behave as specified in the security model.
3.  **Implement comprehensive bounded command parsing.**
    *   Ensure all input from untrusted sources is rigorously validated for size, format, and content to prevent buffer overflows, injection attacks, and logic flaws.
4.  **Implement and test monotonic nonce replay rejection in action engine.**
    *   Confirm that nonces are used correctly and that replayed commands are rejected.
5.  **Implement and test per-channel rate limiting.**
    *   Ensure that denial-of-service attempts via rapid command issuance are mitigated.

---

*This document is generated based on the comparison of `docs/SECURITY_MODEL.md` with currently provided code files. It does not reflect a full security audit but highlights areas for concrete implementation. Additional files (e.g., `atecc608a_driver.c`, bootloader, HID stack) are needed for full implementation of many items.*
