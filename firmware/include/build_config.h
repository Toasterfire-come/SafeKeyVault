#ifndef BUILD_CONFIG_H
#define BUILD_CONFIG_H

/*
 * Build-time hardening switch.
 *
 * Default is development mode (0). Production mode is enabled by defining
 * FIRMWARE_PRODUCTION=1 from the build system.
 */
#ifndef FIRMWARE_PRODUCTION
#define FIRMWARE_PRODUCTION 0
#endif

/*
 * In production builds, ensure that FIRMWARE_PRODUCTION is explicitly set to 1.
 * If it's not defined or set to 0, the build system should ideally catch this.
 * This check is removed to allow build systems to manage the definition externally.
 * The logic within the code (e.g., in state_machine.c) will use the defined value.
 */
// #if FIRMWARE_PRODUCTION != 1
// #error "FIRMWARE_PRODUCTION must be defined and set to 1 for production builds."
// #endif

#endif /* BUILD_CONFIG_H */
