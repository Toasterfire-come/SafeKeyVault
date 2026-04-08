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
    type: "LOGIN_FORM_SUBMIT",
    origin: location.origin,
    username: cred.username,
    password: cred.password
  });
}

document.addEventListener("submit", onSubmitCapture, true);
