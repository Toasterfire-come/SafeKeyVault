#ifndef USB_MSC_H
#define USB_MSC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define USB_HID_KBD_IN_EP           0x81 // Endpoint 1 IN for HID Keyboard
#define USB_HID_CUSTOM_IN_EP        0x82 // Endpoint 2 IN for Custom HID
#define USB_HID_CUSTOM_OUT_EP       0x02 // Endpoint 2 OUT for Custom HID
#define USB_MSC_IN_EP               0x83 // Endpoint 3 IN for Mass Storage
#define USB_MSC_OUT_EP              0x03 // Endpoint 3 OUT for Mass Storage
#define USB_MSC_MAX_LUN             0

void usb_msc_init(void);
void usb_msc_poll(void);
bool usb_msc_get_sector(uint32_t lba, uint8_t *buf);

#endif /* USB_MSC_H */
