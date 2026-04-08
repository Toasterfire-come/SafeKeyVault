"use strict";

async function queryActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs || tabs.length === 0) {
    return null;
  }
  return tabs[0];
}

async function sendToActiveTab(payload) {
  const tab = await queryActiveTab();
  if (!tab || !tab.id) {
    throw new Error("No active tab");
  }
  return chrome.tabs.sendMessage(tab.id, payload);
}

document.getElementById("status").textContent = "Ready";

document.getElementById("connect").addEventListener("click", async () => {
  try {
    document.getElementById("status").textContent = "Connecting...";
    await chrome.runtime.sendMessage({ type: "CONNECT_DEVICE" });
    document.getElementById("status").textContent = "Connected";
  } catch (err) {
    document.getElementById("status").textContent = `Connect failed: ${err.message}`;
  }
});

document.getElementById("requestFill").addEventListener("click", async () => {
  try {
    document.getElementById("status").textContent = "Requesting fill...";
    await sendToActiveTab({ type: "REQUEST_FILL" });
    document.getElementById("status").textContent = "Fill requested";
  } catch (err) {
    document.getElementById("status").textContent = `Fill failed: ${err.message}`;
  }
});

document.getElementById("requestGenerate").addEventListener("click", async () => {
  try {
    document.getElementById("status").textContent = "Requesting generate...";
    await sendToActiveTab({ type: "REQUEST_GENERATE" });
    document.getElementById("status").textContent = "Generate requested";
  } catch (err) {
    document.getElementById("status").textContent = `Generate failed: ${err.message}`;
  }
});

document.getElementById("manualArm").addEventListener("click", async () => {
  try {
    document.getElementById("status").textContent = "Arming manual popup...";
    await chrome.runtime.sendMessage({ type: "ARM_MANUAL_POPUP" });
    document.getElementById("status").textContent = "Manual popup armed";
  } catch (err) {
    document.getElementById("status").textContent = `Manual arm failed: ${err.message}`;
  }
});

document.getElementById("changePin").addEventListener("click", async () => {
  try {
    const oldPin = document.getElementById("oldPin").value.trim();
    const newPin = document.getElementById("newPin").value.trim();
    if (!/^\d{5}$/.test(oldPin) || !/^\d{5}$/.test(newPin)) {
      document.getElementById("status").textContent = "PINs must be exactly 5 digits";
      return;
    }
    document.getElementById("status").textContent = "Requesting PIN change...";
    await chrome.runtime.sendMessage({
      type: "REQUEST_CHANGE_PIN",
      oldPin,
      newPin,
    });
    document.getElementById("status").textContent = "PIN change requested";
    document.getElementById("oldPin").value = "";
    document.getElementById("newPin").value = "";
  } catch (err) {
    document.getElementById("status").textContent = `PIN change failed: ${err.message}`;
  }
});

document.getElementById("confirmTap").addEventListener("click", async () => {
  try {
    document.getElementById("status").textContent = "Confirming tap...";
    await chrome.runtime.sendMessage({ type: "CONFIRM_TAP" });
    document.getElementById("status").textContent = "Tap sent";
  } catch (err) {
    document.getElementById("status").textContent = `Confirm tap failed: ${err.message}`;
  }
});

document.getElementById("confirmHold").addEventListener("click", async () => {
  try {
    document.getElementById("status").textContent = "Confirming hold...";
    await chrome.runtime.sendMessage({ type: "CONFIRM_HOLD" });
    document.getElementById("status").textContent = "Hold sent";
  } catch (err) {
    document.getElementById("status").textContent = `Confirm hold failed: ${err.message}`;
  }
});

