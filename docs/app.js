"use strict";

const MAX_FILE_SIZE = 250 * 1024 * 1024;
const state = { mode: "encrypt", file: null };
const cryptoCore = globalThis.SheeKryptorCrypto;

const elements = {
  modeButtons: [...document.querySelectorAll(".mode-button")],
  fileInput: document.querySelector("#file-input"),
  dropZone: document.querySelector("#drop-zone"),
  dropTitle: document.querySelector("#drop-title"),
  fileChip: document.querySelector("#file-chip"),
  password: document.querySelector("#password"),
  confirmPassword: document.querySelector("#confirm-password"),
  confirmGroup: document.querySelector("#confirm-group"),
  strength: document.querySelector("#strength"),
  actionButton: document.querySelector("#action-button"),
  actionLabel: document.querySelector("#action-label"),
  status: document.querySelector("#status"),
};

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / (1024 ** index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}

function setStatus(message, isError = false) {
  elements.status.textContent = message;
  elements.status.classList.toggle("error", isError);
  elements.status.hidden = false;
}

function clearStatus() {
  elements.status.hidden = true;
  elements.status.classList.remove("error");
  elements.status.textContent = "";
}

function setBusy(busy) {
  elements.actionButton.disabled = busy;
  elements.actionLabel.textContent = busy
    ? (state.mode === "encrypt" ? "Encrypting locally…" : "Decrypting locally…")
    : (state.mode === "encrypt" ? "Encrypt and download" : "Decrypt and download");
}

function updateMode(mode) {
  state.mode = mode;
  clearStatus();
  elements.modeButtons.forEach((button) => {
    const active = button.dataset.mode === mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  elements.confirmGroup.hidden = mode === "decrypt";
  elements.strength.hidden = mode === "decrypt";
  elements.actionLabel.textContent = mode === "encrypt"
    ? "Encrypt and download"
    : "Decrypt and download";
  elements.dropTitle.textContent = mode === "encrypt"
    ? "Choose a file or drop it here"
    : "Choose a .skrypt file or drop it here";
  elements.fileInput.accept = mode === "decrypt" ? ".skrypt" : "";
  elements.password.autocomplete = mode === "encrypt" ? "new-password" : "current-password";
}

function selectFile(file) {
  clearStatus();
  if (!file) {
    state.file = null;
    elements.fileChip.hidden = true;
    return;
  }
  if (file.size > MAX_FILE_SIZE) {
    state.file = null;
    elements.fileInput.value = "";
    elements.fileChip.hidden = true;
    setStatus("This browser edition limits files to 250 MB. Use the desktop app for larger files.", true);
    return;
  }
  state.file = file;
  elements.fileChip.textContent = `${file.name} · ${formatBytes(file.size)}`;
  elements.fileChip.hidden = false;
}

function passwordScore(password) {
  if (!password) return 0;
  let score = 0;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score += 1;
  if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password)) score += 1;
  return Math.min(score, 4);
}

function updateStrength() {
  const score = passwordScore(elements.password.value);
  const labels = ["Enter a strong password", "Weak", "Fair", "Good", "Strong"];
  elements.strength.dataset.score = String(score);
  elements.strength.querySelector("small").textContent = labels[score];
}

function download(data, filename) {
  const url = URL.createObjectURL(new Blob([data], { type: "application/octet-stream" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function encryptSelectedFile(password) {
  const plaintext = new Uint8Array(await state.file.arrayBuffer());
  const encrypted = await cryptoCore.encryptBytes(plaintext, password);
  download(encrypted, `${state.file.name}.skrypt`);
}

async function decryptSelectedFile(password) {
  const encrypted = new Uint8Array(await state.file.arrayBuffer());
  const plaintext = await cryptoCore.decryptBytes(encrypted, password);
  const filename = state.file.name.toLowerCase().endsWith(".skrypt")
    ? state.file.name.slice(0, -8)
    : `${state.file.name}.decrypted`;
  download(plaintext, filename || "decrypted-file");
}

async function runOperation() {
  clearStatus();
  if (!state.file) {
    setStatus("Choose a file first.", true);
    return;
  }
  const password = elements.password.value;
  if (password.length < 12) {
    setStatus("Use a password of at least 12 characters.", true);
    return;
  }
  if (state.mode === "encrypt" && password !== elements.confirmPassword.value) {
    setStatus("The password confirmation does not match.", true);
    return;
  }

  setBusy(true);
  await new Promise((resolve) => requestAnimationFrame(resolve));
  try {
    if (state.mode === "encrypt") {
      await encryptSelectedFile(password);
      setStatus("Encryption complete. Your .skrypt file has been downloaded.");
    } else {
      await decryptSelectedFile(password);
      setStatus("Authentication passed. The recovered file has been downloaded.");
    }
  } catch (error) {
    setStatus(error.message || "The operation could not be completed.", true);
  } finally {
    setBusy(false);
  }
}

elements.modeButtons.forEach((button) => {
  button.addEventListener("click", () => updateMode(button.dataset.mode));
});
elements.fileInput.addEventListener("change", () => selectFile(elements.fileInput.files[0]));
elements.password.addEventListener("input", updateStrength);
elements.actionButton.addEventListener("click", runOperation);

document.querySelectorAll(".reveal-button").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.querySelector(`#${button.dataset.target}`);
    const revealing = input.type === "password";
    const fieldName = button.dataset.target === "confirm-password"
      ? "confirmation password"
      : "password";
    input.type = revealing ? "text" : "password";
    button.textContent = revealing ? "Hide" : "Show";
    button.setAttribute(
      "aria-label",
      `${revealing ? "Hide" : "Show"} ${fieldName}`,
    );
  });
});

["dragenter", "dragover"].forEach((eventName) => {
  elements.dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropZone.classList.add("dragging");
  });
});

["dragleave", "drop"].forEach((eventName) => {
  elements.dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    elements.dropZone.classList.remove("dragging");
  });
});

elements.dropZone.addEventListener("drop", (event) => {
  selectFile(event.dataTransfer.files[0]);
});

updateMode("encrypt");
updateStrength();
