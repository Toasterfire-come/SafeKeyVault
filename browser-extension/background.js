"use strict";

const VENDOR_ID = 0xCAFE;
const PRODUCT_ID = 0x2040;
const REPORT_ID = 1;
const MAX_PAYLOAD = 190;

let device = null;

function encodeJsonCommand(obj) {
  const json = JSON.stringify(obj);
  const bytes = new TextEncoder().encode(json);
  if (bytes.length > MAX_PAYLOAD) {
    throw new Error("Command payload too large");
  }
  const packet = new Uint8Array(1 + MAX_PAYLOAD);
  packet[0] = bytes.length;
  packet.set(bytes, 1);
  return packet;
}

async function ensureDevice() {
  if (device && device.opened) return device;
  const devices = await navigator.hid.getDevices();
  device = devices.find((d) =>
    d.collections.some((c) => c.usagePage === 0xff00)
  );
  if (!device) {
    const requested = await navigator.hid.requestDevice({
      filters: [{ vendorId: VENDOR_ID, productId: PRODUCT_ID }],
    });
    device = requested[0] || null;
  }
  if (!device) {
    throw new Error("Device not found");
  }
  if (!device.opened) {
    await device.open();
  }
  return device;
}

async function sendCommand(command) {
  const dev = await ensureDevice();
  const packet = encodeJsonCommand(command);
  await dev.sendReport(REPORT_ID, packet);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (!msg || typeof msg !== "object") {
      sendResponse({ ok: false, error: "invalid message" });
      return;
    }

    if (msg.type === "ARM_MANUAL_POPUP") {
      await sendCommand({ t: "arm_manual_popup" });
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "REQUEST_FILL") {
      await sendCommand({ t: "request_fill", origin: msg.origin || "" });
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "REQUEST_SAVE") {
      await sendCommand({
        t: "request_save",
        origin: msg.origin || "",
        username: msg.username || "",
        password: msg.password || "",
      });
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "REQUEST_GENERATE") {
      await sendCommand({
        t: "request_generate",
        origin: msg.origin || "",
        username: msg.username || "",
      });
      sendResponse({ ok: true });
      return;
    }

    sendResponse({ ok: false, error: "unknown command" });
  })().catch((err) => {
    sendResponse({ ok: false, error: String(err && err.message ? err.message : err) });
  });
  return true;
});
