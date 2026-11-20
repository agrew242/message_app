// A made-up holiday photo for the screenshots: a sunset over a lake, painted
// on a canvas in the page, so the repository needs no image file for it.

/** Paints the picture in `page` and returns it as JPEG bytes. */
export async function paintLakePhoto(page) {
  const base64 = await page.evaluate(async () => {
    const w = 1600;
    const h = 1200;
    const horizon = Math.round(h * 0.6);
    const c = document.createElement('canvas');
    c.width = w;
    c.height = h;
    const g = c.getContext('2d');
    let seed = 11;
    const rnd = () => (seed = (seed * 16807) % 2147483647) / 2147483647;

    // Sky and sun.
    const sky = g.createLinearGradient(0, 0, 0, horizon);
    sky.addColorStop(0, '#1d2b64');
    sky.addColorStop(0.45, '#7b4397');
    sky.addColorStop(0.78, '#f0686a');
    sky.addColorStop(1, '#fbb36b');
    g.fillStyle = sky;
    g.fillRect(0, 0, w, horizon);
    const sun = { x: w * 0.64, y: horizon - 70, r: 62 };
    const glow = g.createRadialGradient(sun.x, sun.y, sun.r * 0.5, sun.x, sun.y, sun.r * 7);
    glow.addColorStop(0, 'rgba(255, 236, 190, 0.85)');
    glow.addColorStop(1, 'rgba(255, 180, 120, 0)');
    g.fillStyle = glow;
    g.fillRect(0, 0, w, horizon);
    g.fillStyle = '#fff4d8';
    g.beginPath();
    g.arc(sun.x, sun.y, sun.r, 0, Math.PI * 2);
    g.fill();

    // Three ridges of hills, further ones paler.
    const ridge = (top, amp, color, f, phase) => {
      g.fillStyle = color;
      g.beginPath();
      g.moveTo(0, horizon);
      for (let x = 0; x <= w; x += 4) {
        const wave = 0.55 * Math.sin(x * f + phase) + 0.3 * Math.sin(x * f * 2.7 + phase * 1.9) + 0.15 * Math.sin(x * f * 7.3);
        g.lineTo(x, top - amp * wave);
      }
      g.lineTo(w, horizon);
      g.closePath();
      g.fill();
    };
    ridge(horizon - 140, 80, '#a05a86', 0.004, 1.2);
    ridge(horizon - 85, 70, '#5c3770', 0.006, 3.1);
    ridge(horizon - 28, 34, '#2c1d45', 0.009, 0.4);

    // Pines along the near shore.
    g.fillStyle = '#1a1230';
    for (let x = -10; x < w * 0.4; x += 12 + rnd() * 12) {
      const tall = 40 + rnd() * 100;
      g.beginPath();
      g.moveTo(x - tall * 0.2, horizon + 2);
      g.lineTo(x, horizon - tall);
      g.lineTo(x + tall * 0.2, horizon + 2);
      g.closePath();
      g.fill();
    }

    // The lake: everything above, upside down and darker, with glints.
    g.save();
    g.translate(0, horizon * 2);
    g.scale(1, -1);
    g.globalAlpha = 0.6;
    g.drawImage(c, 0, 0, w, horizon, 0, 0, w, horizon);
    g.restore();
    const water = g.createLinearGradient(0, horizon, 0, h);
    water.addColorStop(0, 'rgba(20, 14, 48, 0.3)');
    water.addColorStop(1, 'rgba(10, 8, 30, 0.85)');
    g.fillStyle = water;
    g.fillRect(0, horizon, w, h - horizon);
    for (let i = 0; i < 80; i++) {
      const depth = Math.pow(rnd(), 1.5) * (h - horizon - 20);
      const y = horizon + 6 + depth;
      const x = sun.x + (rnd() - 0.5) * (60 + depth * 1.4);
      const len = (20 + rnd() * 60) * (1 + depth / 220);
      g.strokeStyle = `rgba(255, 222, 170, ${0.15 + rnd() * 0.45})`;
      g.lineWidth = 2 + depth / 110;
      g.beginPath();
      g.moveTo(x - len / 2, y);
      g.lineTo(x + len / 2, y);
      g.stroke();
    }

    const blob = await new Promise((r) => c.toBlob(r, 'image/jpeg', 0.9));
    const bytes = new Uint8Array(await blob.arrayBuffer());
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s);
  });
  return Buffer.from(base64, 'base64');
}
