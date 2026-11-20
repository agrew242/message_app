// Scanning a friend's verification QR code with the camera.
//
// Safari has no built-in barcode reader, so frames go through jsQR
// (vendor/jsQR.js, loaded as a plain script in index.html).

import { namedError } from './store.js';

const SCAN_SIDE = 640;

function el(tag, style, text) {
  const node = document.createElement(tag);
  Object.assign(node.style, style);
  if (text) node.textContent = text;
  return node;
}

/** Shows a camera view until a QR code is found. Resolves to its text, or null if cancelled. */
export async function scanQrCode() {
  if (!navigator.mediaDevices?.getUserMedia) throw namedError('Unsupported', "This browser can't use the camera");
  if (typeof window.jsQR !== 'function') throw namedError('Unsupported', 'The QR reader failed to load');

  const overlay = el('div', {
    position: 'fixed',
    inset: '0',
    zIndex: '2147483647',
    background: '#000',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '16px',
    fontFamily: 'system-ui, -apple-system, sans-serif',
  });
  const video = el('video', { maxWidth: '100%', maxHeight: '70%', borderRadius: '12px' });
  video.setAttribute('playsinline', '');
  video.muted = true;
  const hint = el('div', { color: '#fff', fontSize: '16px' }, "Point the camera at your friend's code");
  const cancel = el(
    'button',
    {
      fontSize: '17px',
      padding: '10px 28px',
      borderRadius: '22px',
      border: 'none',
      background: '#fff',
      color: '#000',
    },
    'Cancel',
  );
  overlay.append(video, hint, cancel);
  document.body.append(overlay);

  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
    video.srcObject = stream;
    await video.play();
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    return await new Promise((resolve) => {
      let stopped = false;
      cancel.onclick = () => {
        stopped = true;
        resolve(null);
      };
      const tick = () => {
        if (stopped) return;
        if (video.readyState >= 2 && video.videoWidth) {
          const scale = Math.min(1, SCAN_SIDE / Math.max(video.videoWidth, video.videoHeight));
          canvas.width = Math.round(video.videoWidth * scale);
          canvas.height = Math.round(video.videoHeight * scale);
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          const frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = window.jsQR(frame.data, frame.width, frame.height, { inversionAttempts: 'dontInvert' });
          if (code?.data) {
            stopped = true;
            resolve(code.data);
            return;
          }
        }
        requestAnimationFrame(tick);
      };
      tick();
    });
  } catch (e) {
    if (e?.name === 'NotAllowedError') throw namedError('Denied', 'Camera access is turned off for this app');
    throw e;
  } finally {
    stream?.getTracks().forEach((t) => t.stop());
    overlay.remove();
  }
}
