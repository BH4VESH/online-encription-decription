(() => {
  const $ = (selector) => document.querySelector(selector);

  function setStatus(id, message, type = '') {
    const element = $(`#${id}`);
    element.textContent = message;
    element.className = `help ${type}`.trim();
  }

  async function submitForm(form, endpoint, outputId, statusId) {
    const button = form.querySelector('button[type="submit"]');
    const formData = new FormData(form);
    const payload = Object.fromEntries(formData.entries());
    if (form.id === 'decrypt-form') payload.inputFormat = formData.get('inputFormat');
    button.disabled = true;
    setStatus(statusId, 'Processing…');
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify(payload),
        credentials: 'same-origin'
      });
      const result = await response.json();
      if (!response.ok || !result.status) throw new Error(result.message || 'Request failed.');
      $(`#${outputId}`).value = typeof result.data === 'string' ? result.data : JSON.stringify(result.data, null, 2);
      setStatus(statusId, result.message, 'success');
    } catch (error) {
      $(`#${outputId}`).value = '';
      setStatus(statusId, error.message || 'Request failed.', 'error');
    } finally {
      button.disabled = false;
    }
  }

  $('#encrypt-form').addEventListener('submit', (event) => {
    event.preventDefault();
    submitForm(event.currentTarget, '/api/encrypt', 'encrypt-output', 'encrypt-status');
  });
  $('#decrypt-form').addEventListener('submit', (event) => {
    event.preventDefault();
    submitForm(event.currentTarget, '/api/decrypt', 'decrypt-output', 'decrypt-status');
  });

  $('#base64-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    setStatus('base64-status', 'Processing…');
    try {
      const response = await fetch('/api/base64', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ text: $('#base64-input').value, action: $('#base64-action').value }),
        credentials: 'same-origin'
      });
      const result = await response.json();
      if (!response.ok || !result.status) throw new Error(result.message || 'Conversion failed.');
      $('#base64-output').value = result.data;
      setStatus('base64-status', result.message, 'success');
    } catch (error) {
      $('#base64-output').value = '';
      setStatus('base64-status', error.message || 'Conversion failed.', 'error');
    } finally {
      button.disabled = false;
    }
  });

  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      const target = $(`#${button.dataset.copy}`);
      if (!target.value) return;
      try {
        await navigator.clipboard.writeText(target.value);
        button.textContent = 'Copied';
        setTimeout(() => { button.textContent = 'Copy'; }, 1200);
      } catch {
        target.select();
        document.execCommand('copy');
      }
    });
  });

  document.querySelectorAll('[data-generate-key]').forEach((button) => {
    button.addEventListener('click', () => {
      const side = button.dataset.generateKey;
      const size = Number($(`#${side}-key-size`).value);
      const format = $(`#${side}-key-format`).value;
      const bytes = cryptoBytes(size / 8);
      $(`#${side}-key`).value = encodeBytes(bytes, format);
      $(`#${side}-key`).type = 'text';
    });
  });

  document.querySelectorAll('[data-generate-iv]').forEach((button) => {
    button.addEventListener('click', () => {
      const side = button.dataset.generateIv;
      const mode = $(`#${side}-mode`).value;
      const format = $(`#${side}-iv-format`).value;
      $(`#${side}-iv`).value = encodeBytes(cryptoBytes(mode === 'gcm' ? 12 : 16), format);
    });
  });

  function cryptoBytes(length) {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    return bytes;
  }
function encodeBytes(bytes, format) {
  if (format === "hex") {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  if (format === "base64") {
    let binary = "";
    bytes.forEach((b) => {
      binary += String.fromCharCode(b);
    });
    return btoa(binary);
  }

  if (format === "plain") {
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    let result = "";
    const maxValid = 256 - (256 % chars.length);

    while (result.length < bytes.length) {
      const randomBytes = cryptoBytes(bytes.length * 2);

      for (const byte of randomBytes) {
        if (byte >= maxValid) continue;

        result += chars[byte % chars.length];

        if (result.length === bytes.length) break;
      }
    }

    return result;
  }

  throw new Error(`Unsupported format: ${format}`);
}
  ['encrypt', 'decrypt'].forEach((side) => {
    $(`#${side}-mode`).addEventListener('change', () => {
      const mode = $(`#${side}-mode`).value;
      if (mode === 'gcm') {
        const format = $(`#${side}-iv-format`);
        format.value = 'base64';
      }
    });
  });
})();