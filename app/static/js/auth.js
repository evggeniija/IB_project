"use strict";

/**
 * Thin fetch wrappers around the existing JSON auth API. This file never
 * re-implements registration/login/session logic -- it only calls
 * POST /api/auth/register, /login, /logout and reacts to their responses.
 */

async function postJSON(url, body) {
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  let data = null;
  try {
    data = await response.json();
  } catch (err) {
    data = null;
  }

  return { ok: response.ok, status: response.status, data };
}

function showError(el, message) {
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
}

function hideError(el) {
  if (!el) return;
  el.hidden = true;
  el.textContent = "";
}

// The API's `detail` field is already a short, generic, safe-to-display
// string for the error cases these forms hit (401/404/409). A non-string
// `detail` (FastAPI's structured 422 validation errors) is never shown
// verbatim -- fall back to a generic message instead.
function friendlyDetail(data, fallback) {
  if (data && typeof data.detail === "string") {
    return data.detail;
  }
  return fallback;
}

function setupLoginForm() {
  const form = document.getElementById("login-form");
  if (!form) return;
  const errorEl = document.getElementById("form-error");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideError(errorEl);

    const email = form.email.value.trim();
    const password = form.password.value;

    const { ok, data } = await postJSON("/api/auth/login", { email, password });
    if (ok) {
      window.location.href = "/dashboard";
      return;
    }
    showError(errorEl, friendlyDetail(data, "Login failed. Please check your email and password."));
  });
}

function setupRegisterForm() {
  const form = document.getElementById("register-form");
  if (!form) return;
  const errorEl = document.getElementById("form-error");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideError(errorEl);

    const email = form.email.value.trim();
    const password = form.password.value;
    const confirmInput = form.elements.namedItem("confirm_password");

    if (confirmInput && confirmInput.value !== password) {
      showError(errorEl, "Passwords do not match.");
      return;
    }

    const { ok, data } = await postJSON("/api/auth/register", { email, password });
    if (ok) {
      window.location.href = "/login";
      return;
    }
    showError(
      errorEl,
      friendlyDetail(data, "Registration failed. Please check your details and try again.")
    );
  });
}

function setupLogoutButton() {
  const button = document.getElementById("logout-button");
  if (!button) return;

  button.addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    window.location.href = "/login";
  });
}

setupLoginForm();
setupRegisterForm();
setupLogoutButton();
