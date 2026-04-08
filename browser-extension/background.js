"use strict";

const VENDOR_ID = 0xCAFE;
const PRODUCT_ID = 0x2040;
const REPORT_ID = 1;
const MAX_PAYLOAD = 190;
const NONCE_KEY = "lastNonce";
const MAX_ORIGIN = 95;
const MAX_USERNAME = 95;
const MAX_PASSWORD = 127;

let device = null;
let nonce = 1;

chrome.storage.local.get([NONCE_KEY]).then((items) => {
  const stored = Number(items[NONCE_KEY] || 0);
  nonce = Number.isFinite(stored) && stored > 0 ? stored + 1 : 1;
}).catch(() => {
  nonce = 1;
});

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
  const withNonce = { ...command, nonce };
  const packet = encodeJsonCommand(withNonce);
  await dev.sendReport(REPORT_ID, packet);
  await chrome.storage.local.set({ [NONCE_KEY]: nonce });
  nonce += 1;
}

function sanitizeField(value, maxLen) {
  const text = String(value || "");
  return text.slice(0, maxLen);
}

function isHttpsOrigin(origin) {
  try {
    const url = new URL(origin);
    return url.protocol === "https:";
  } catch {
    return false;
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (!msg || typeof msg !== "object") {
      sendResponse({ ok: false, error: "invalid message" });
      return;
    }

    if (msg.type === "CONNECT_DEVICE") {
      await ensureDevice();
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "ARM_MANUAL_POPUP") {
      await sendCommand({ t: "arm_manual_popup" });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === "CONFIRM_TAP") {
      await sendCommand({ t: "confirm_tap" });
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "CONFIRM_HOLD") {
      await sendCommand({ t: "confirm_hold" });
      sendResponse({ ok: true });
      return;
    }


    if (msg.type === "REQUEST_FILL") {
      const origin = sanitizeField(msg.origin, MAX_ORIGIN);
      if (!isHttpsOrigin(origin)) {
        throw new Error("origin must be https");
      }
      await sendCommand({ t: "request_fill", origin });
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "REQUEST_SAVE") {
      const origin = sanitizeField(msg.origin, MAX_ORIGIN);
      const username = sanitizeField(msg.username, MAX_USERNAME);
      const password = sanitizeField(msg.password, MAX_PASSWORD);
      if (!isHttpsOrigin(origin)) {
        throw new Error("origin must be https");
      }
      if (!username || !password) {
        throw new Error("missing username/password");
      }
      await sendCommand({
        t: "request_save",
        origin,
        username,
        password,
      });
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "REQUEST_GENERATE") {
      const origin = sanitizeField(msg.origin, MAX_ORIGIN);
      const username = sanitizeField(msg.username, MAX_USERNAME);
      if (!isHttpsOrigin(origin)) {
        throw new Error("origin must be https");
      }
      await sendCommand({
        t: "request_generate",
        origin,
        username,
      });
      sendResponse({ ok: true });
      return;
    }

    if (msg.type === "REQUEST_CHANGE_PIN") {
      await sendCommand({
        t: "change_pin",
        old_pin: msg.oldPin || "",
        new_pin: msg.newPin || "",
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
