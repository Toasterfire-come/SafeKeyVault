"use strict";

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
  const username = String(usernameInput.value || "");
  const password = String(passwordInput.value || "");
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
  if (!cred) {
    return;
  }
  chrome.runtime.sendMessage({
    type: "REQUEST_SAVE",
    origin: location.origin,
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
    chrome.runtime.sendMessage({
      type: "REQUEST_FILL",
      origin: location.origin
    }).then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err && err.message ? err.message : err) }));
    return true;
  }
  if (msg.type === "REQUEST_SAVE") {
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
      origin: location.origin,
      username: cred.username,
      password: cred.password
    }).then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String(err && err.message ? err.message : err) }));
    return true;
  }
  if (msg.type === "REQUEST_GENERATE") {
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
      origin: location.origin,
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
