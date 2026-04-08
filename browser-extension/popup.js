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

document.getElementById("btnFill").addEventListener("click", async () => {
  try {
    document.getElementById("status").textContent = "Requesting fill...";
    await sendToActiveTab({ type: "REQUEST_FILL" });
    document.getElementById("status").textContent = "Fill requested";
  } catch (err) {
    document.getElementById("status").textContent = `Fill failed: ${err.message}`;
  }
});

document.getElementById("btnSave").addEventListener("click", async () => {
  try {
    document.getElementById("status").textContent = "Requesting save...";
    await sendToActiveTab({ type: "REQUEST_SAVE" });
    document.getElementById("status").textContent = "Save requested";
  } catch (err) {
    document.getElementById("status").textContent = `Save failed: ${err.message}`;
  }
});

document.getElementById("btnGenerate").addEventListener("click", async () => {
  try {
    document.getElementById("status").textContent = "Requesting generate...";
    await sendToActiveTab({ type: "REQUEST_GENERATE" });
    document.getElementById("status").textContent = "Generate requested";
  } catch (err) {
    document.getElementById("status").textContent = `Generate failed: ${err.message}`;
  }
});

