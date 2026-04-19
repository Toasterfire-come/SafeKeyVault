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

#if FIRMWARE_PRODUCTION != 1
#error "FIRMWARE_PRODUCTION must be defined and set to 1 for production builds."
#endif

#endif /* BUILD_CONFIG_H */
