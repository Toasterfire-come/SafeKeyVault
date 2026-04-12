#ifndef USB_MSC_H
#define USB_MSC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define USB_MSC_EP_OUT 0x02
#define USB_MSC_EP_IN 0x82
#define USB_MSC_MAX_LUN 0

void usb_msc_init(void);
void usb_msc_poll(void);
bool usb_msc_get_sector(uint32_t lba, uint8_t *buf);

#endif /* USB_MSC_H */
