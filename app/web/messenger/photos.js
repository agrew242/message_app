// Picking and preparing photos.
//
// Photos are re-drawn through a canvas before sending. That shrinks them to
// a sensible size and, as a side effect, drops their metadata (including
// where they were taken).

const MAX_SIDE = 2048;
const THUMB_SIDE = 48;

/**
 * Opens the photo picker. Call it straight from a tap: browsers only allow
 * pickers in response to one. Resolves to a File, or null if cancelled.
 */
export function pickImageFile() {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'image/*';
    input.style.display = 'none';
    document.body.appendChild(input);
    let done = false;
    const finish = (file) => {
      if (done) return;
      done = true;
      input.remove();
      resolve(file);
    };
    input.addEventListener('change', () => finish(input.files?.[0] ?? null));
    input.addEventListener('cancel', () => finish(null));
    input.click();
  });
}

function draw(source, width, height) {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#fff'; // transparent PNGs become JPEGs
  ctx.fillRect(0, 0, width, height);
  ctx.drawImage(source, 0, 0, width, height);
  return canvas;
}

function fit(width, height, max) {
  const scale = Math.min(1, max / Math.max(width, height));
  return [Math.max(1, Math.round(width * scale)), Math.max(1, Math.round(height * scale))];
}

/** Resizes to at most 2048px, re-encodes as JPEG, and makes a thumbnail. */
export async function preparePhoto(file) {
  let bitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch {
    const e = new Error("That photo couldn't be opened");
    e.name = 'Invalid';
    throw e;
  }
  try {
    const [w, h] = fit(bitmap.width, bitmap.height, MAX_SIDE);
    const blob = await new Promise((resolve) => draw(bitmap, w, h).toBlob(resolve, 'image/jpeg', 0.85));
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const [tw, th] = fit(w, h, THUMB_SIDE);
    const thumbnail = draw(bitmap, tw, th).toDataURL('image/jpeg', 0.6);
    return { bytes, info: { mime: 'image/jpeg', width: w, height: h, thumbnail } };
  } finally {
    bitmap.close?.();
  }
}
