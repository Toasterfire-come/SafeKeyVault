# Security Implementation To-Do List

## Secure Boot and Signed Update Flow

1. **Implement a secure update mechanism.**
   * Develop a mechanism to securely download, verify (using `crypto_engine_ecdsa_verify`), and install firmware updates.

## Authenticated HID Session/Channel Binding

1. **Design and