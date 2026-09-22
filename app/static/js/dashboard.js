"use strict";

/**
 * Dashboard messaging UI: send, inbox listing, and decrypt.
 *
 * This only ever calls the existing JSON API (POST /api/messages,
 * GET /api/messages/inbox, POST /api/messages/{id}/decrypt) -- it never
 * re-implements sender/message-id/timestamp logic, and it never does any
 * cryptography itself. Sender identity, message id, and timestamp are
 * always server-generated; this file only ever sends {recipient, message}.
 *
 * Sender email and decrypted plaintext are untrusted, user-controlled
 * data, so every dynamic value is rendered with safe DOM text APIs
 * (createElement + textContent), never raw HTML insertion, to avoid XSS.
 * Nothing here writes to any browser-side persistent storage, including
 * decrypted plaintext, which only ever exists in the current page's DOM.
 */

async function apiRequest(method, url, body) {
  const options = {
    method,
    credentials: "same-origin",
  };
  if (body !== undefined) {
    options.headers = { "Content-Type": "application/json" };
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);
  let data = null;
  try {
    data = await response.json();
  } catch (err) {
    data = null;
  }
  return { ok: response.ok, status: response.status, data };
}

function friendlyDetail(data, fallback) {
  if (data && typeof data.detail === "string") {
    return data.detail;
  }
  return fallback;
}

function formatTimestamp(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function createMessageItem(message) {
  const item = document.createElement("li");
  item.className = "inbox-item";

  const meta = document.createElement("div");
  meta.className = "inbox-item-meta";

  const sender = document.createElement("span");
  sender.className = "inbox-item-sender";
  sender.textContent = message.sender;

  const timestamp = document.createElement("span");
  timestamp.className = "inbox-item-timestamp";
  timestamp.textContent = formatTimestamp(message.timestamp);

  const status = document.createElement("span");
  status.className = "inbox-item-status";
  status.textContent = message.processed ? "Processed" : "Unread";

  meta.appendChild(sender);
  meta.appendChild(timestamp);
  meta.appendChild(status);

  const body = document.createElement("div");
  body.className = "inbox-item-body";

  item.appendChild(meta);
  item.appendChild(body);

  if (message.processed) {
    const note = document.createElement("p");
    note.className = "inbox-item-note";
    note.textContent = "Already decrypted in a previous session.";
    body.appendChild(note);
  } else {
    const decryptButton = document.createElement("button");
    decryptButton.type = "button";
    decryptButton.className = "decrypt-button";
    decryptButton.textContent = "Decrypt";
    decryptButton.addEventListener("click", () => {
      handleDecrypt(message.message_id, status, body, decryptButton);
    });
    body.appendChild(decryptButton);
  }

  return item;
}

async function handleDecrypt(messageId, statusEl, body, button) {
  button.disabled = true;

  const { ok, status: httpStatus, data } = await apiRequest(
    "POST",
    `/api/messages/${encodeURIComponent(messageId)}/decrypt`
  );

  if (ok) {
    statusEl.textContent = "Processed";
    button.remove();

    const plaintextEl = document.createElement("p");
    plaintextEl.className = "inbox-item-plaintext";
    plaintextEl.textContent = data && typeof data.plaintext === "string" ? data.plaintext : "";
    body.appendChild(plaintextEl);
    return;
  }

  if (httpStatus === 409) {
    statusEl.textContent = "Processed";
    button.remove();

    const note = document.createElement("p");
    note.className = "inbox-item-note";
    note.textContent = "Message has already been decrypted.";
    body.appendChild(note);
    return;
  }

  button.disabled = false;
  const errorEl = document.createElement("p");
  errorEl.className = "inbox-item-error";
  errorEl.textContent = friendlyDetail(data, "Unable to decrypt this message.");
  body.appendChild(errorEl);
}

async function loadInbox() {
  const list = document.getElementById("inbox-list");
  const emptyEl = document.getElementById("inbox-empty");
  const errorEl = document.getElementById("inbox-error");
  if (!list) return;

  list.textContent = "";
  if (errorEl) errorEl.hidden = true;
  if (emptyEl) emptyEl.hidden = true;

  const { ok, data } = await apiRequest("GET", "/api/messages/inbox");

  if (!ok || !Array.isArray(data)) {
    if (errorEl) {
      errorEl.textContent = "Unable to load inbox right now.";
      errorEl.hidden = false;
    }
    return;
  }

  if (data.length === 0) {
    if (emptyEl) emptyEl.hidden = false;
    return;
  }

  for (const message of data) {
    list.appendChild(createMessageItem(message));
  }
}

function setupSendForm() {
  const form = document.getElementById("send-form");
  if (!form) return;
  const errorEl = document.getElementById("send-error");
  const successEl = document.getElementById("send-success");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    errorEl.hidden = true;
    successEl.hidden = true;

    // Only recipient + plaintext are ever sent. Sender, message id, and
    // timestamp are never supplied by the browser -- the server derives
    // sender from the session and generates the id/timestamp itself.
    const recipient = form.recipient.value.trim();
    const message = form.message.value;

    const { ok, data } = await apiRequest("POST", "/api/messages", { recipient, message });

    if (ok) {
      form.message.value = ""; // never keep sent plaintext in the browser
      successEl.textContent = "Message sent.";
      successEl.hidden = false;
      loadInbox();
      return;
    }

    errorEl.textContent = friendlyDetail(
      data,
      "Unable to send message. Please check the recipient and try again."
    );
    errorEl.hidden = false;
  });
}

setupSendForm();
loadInbox();
