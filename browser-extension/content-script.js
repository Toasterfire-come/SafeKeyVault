"use strict";

const MAX_ORIGIN_LEN = 95;
const MAX_USERNAME_LEN = 95;
const MAX_PASSWORD_LEN = 127;

function sanitizeField(value, maxLen) {
  const raw = String(value || "");
  const trimmed = raw.trim();
  const cleaned = trimmed.replace(/[\u0000-\u001F\u007F]/g, "");
  return cleaned.slice(0, maxLen);
}

function safePageOrigin() {
  let origin = "";
  try {
    origin = String(location.origin || "");
  } catch (_err) {
    return "";
  }
  if (!origin.startsWith("https://")) {
    return "";
  }
  if (origin.length > MAX_ORIGIN_LEN) {
    return "";
  }
  if (origin.includes("@")) {
    return "";
  }
  return origin;
}

function looksLikeLoginForm(form) {
  if (!(form instanceof HTMLFormElement)) {
    return false;
  }
  const pw = form.querySelector('input[type="password"]');
  if (!pw) {
    return false;
  }
  const user = form.querySelector('input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i]');
  return Boolean(user);
}

function getCandidateCredential(form) {
  const usernameInput = form.querySelector('input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i]');
  const passwordInput = form.querySelector('input[type="password"]');
  if (!usernameInput || !passwordInput) {
    return null;
  }
  const username = sanitizeField(usernameInput.value, MAX_USERNAME_LEN);
  const password = sanitizeField(passwordInput.value, MAX_PASSWORD_LEN);
  if (!username || !password) {
    return null;
  }
  return { username, password };
}

function onSubmitCapture(event) {
  const form = event.target;
  if (!looksLikeLoginForm(form)) {
    return;
  }
  const cred = getCandidateCredential(form);
  const origin = safePageOrigin();
  if (!origin) {
    return;
  }
  if (!cred) {
    return;
  }
  chrome.runtime.sendMessage({
    type: "REQUEST_SAVE",
    origin,
    username: cred.username,
    password: cred.password
  });
}

document.addEventListener("submit", onSubmitCapture, true);

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || typeof msg !== "object") {
    sendResponse({ ok: false, error: "invalid message" });
    return false;
  }
  if (msg.type === "REQUEST_FILL") {
    const origin = safePageOrigin();
    if (!origin) {
      sendResponse({ ok: false, error: "unsupported origin" });
      return false;
    }
    chrome.runtime.sendMessage({
      type: "REQUEST_FILL",
      origin
    }).then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err && err.message ? err.message : err) }));
    return true;
  }
  if (msg.type === "REQUEST_SAVE") {
    const origin = safePageOrigin();
    if (!origin) {
      sendResponse({ ok: false, error: "unsupported origin" });
      return false;
    }
    const forms = Array.from(document.querySelectorAll("form"));
    const form = forms.find((f) => looksLikeLoginForm(f));
    if (!form) {
      sendResponse({ ok: false, error: "no login form found" });
      return false;
    }
    const cred = getCandidateCredential(form);
    if (!cred) {
      sendResponse({ ok: false, error: "missing username/password value" });
      return false;
    }
    chrome.runtime.sendMessage({
      type: "REQUEST_SAVE",
      origin,
      username: cred.username,
      password: cred.password
    }).then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err && err.message ? err.message : err) }));
    return true;
  }
  if (msg.type === "REQUEST_GENERATE") {
    const origin = safePageOrigin();
    if (!origin) {
      sendResponse({ ok: false, error: "unsupported origin" });
      return false;
    }
    const forms = Array.from(document.querySelectorAll("form"));
    const form = forms.find((f) => looksLikeLoginForm(f));
    let username = "";
    if (form) {
      const cred = getCandidateCredential(form);
      if (cred) {
        username = cred.username;
      }
    }
    chrome.runtime.sendMessage({
      type: "REQUEST_GENERATE",
      origin,
      username
    }).then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err && err.message ? err.message : err) }));
    return true;
  }
  if (msg.type === "ARM_MANUAL_POPUP") {
    chrome.runtime.sendMessage({ type: "ARM_MANUAL_POPUP" })
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err && err.message ? err.message : err) }));
    return true;
  }
  sendResponse({ ok: false, error: "unsupported content command" });
  return false;
});
