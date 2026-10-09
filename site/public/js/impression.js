// A wax impression drawn live on a canvas laid over the photographed seal's blank field. The design comes from real bytes
// (the agent's public key for the seal, the approval for the counterseal), drawn as a height map and lit from the top
// left like the photograph, so it reads as pressed into the wax. Canvas 2D only; no images, no HTML strings.
const S = 512;

function heightMap(kind, bytes, ring) {
  const c = new OffscreenCanvasLike(S, S), g = c.ctx;
  g.fillStyle = '#000'; g.fillRect(0, 0, S, S);
  g.strokeStyle = '#fff'; g.fillStyle = '#fff'; g.lineCap = 'round'; g.lineJoin = 'round';
  const C = S / 2, R = S / 2 * 0.985;
  const circle = (r, w) => { g.lineWidth = w; g.beginPath(); g.arc(C, C, r, 0, Math.PI * 2); g.stroke(); };
  circle(R * 0.95, R * 0.03);
  circle(R * 0.73, R * 0.014);
  // ring text, centred at the top
  g.font = `600 ${Math.round(R * 0.088)}px Geist, system-ui, sans-serif`;
  g.textAlign = 'center'; g.textBaseline = 'middle';
  const chars = [...ring], rr = R * 0.84, gap = R * 0.018;
  const widths = chars.map((ch) => g.measureText(ch).width + gap);
  const total = widths.reduce((a, b) => a + b, 0);
  let a = -Math.PI / 2 - total / rr / 2;
  for (let i = 0; i < chars.length; i++) {
    const mid = a + widths[i] / 2 / rr;
    g.save(); g.translate(C + rr * Math.cos(mid), C + rr * Math.sin(mid)); g.rotate(mid + Math.PI / 2); g.fillText(chars[i], 0, 0); g.restore();
    a += widths[i] / rr;
  }
  const b = (i) => bytes[i % bytes.length] / 255;
  if (kind === 'seal') {
    // a rosette whose petal count, lengths and twist come from the key
    const n = 7 + Math.floor(b(0) * 6), twist = (b(1) - 0.5) * 0.5;
    for (let k = 0; k < n; k++) {
      const ang = (k / n) * Math.PI * 2 - Math.PI / 2, len = R * (0.44 + 0.2 * b(k + 2)), w = 0.16 + 0.14 * b(k + 9);
      g.lineWidth = R * 0.026; g.beginPath();
      for (let t = 0; t <= 1.0001; t += 0.04) { const r = R * 0.1 + len * t, s = w * Math.sin(Math.PI * t); g.lineTo(C + r * Math.cos(ang + s + twist * t), C + r * Math.sin(ang + s + twist * t)); }
      for (let t = 1; t >= -0.0001; t -= 0.04) { const r = R * 0.1 + len * t, s = w * Math.sin(Math.PI * t); g.lineTo(C + r * Math.cos(ang - s + twist * t), C + r * Math.sin(ang - s + twist * t)); }
      g.closePath(); g.stroke();
    }
    const dots = n * 2;
    for (let k = 0; k < dots; k++) {
      const ang = (k / dots) * Math.PI * 2 - Math.PI / 2 + Math.PI / dots, r = R * 0.665, d = R * (0.018 + 0.016 * b(k + 17));
      g.beginPath(); g.arc(C + r * Math.cos(ang), C + r * Math.sin(ang), d, 0, Math.PI * 2); g.fill();
    }
    g.beginPath(); g.arc(C, C, R * 0.07, 0, Math.PI * 2); g.fill();
  } else {
    // a whorl, like the ridges of a fingertip, shaped by the approval's bytes
    const n = 15, ox = (b(3) - 0.5) * R * 0.08, oy = (b(4) - 0.5) * R * 0.08;
    g.lineWidth = R * 0.017;
    for (let i = 0; i < n; i++) {
      const r0 = R * (0.05 + i * 0.041); g.beginPath();
      for (let t = 0; t <= 360; t += 3) {
        const th = (t * Math.PI) / 180;
        const r = r0 * (1 + 0.1 * Math.sin(2 * th + i * 0.35 + b(i) * 3) + 0.05 * Math.sin(3 * th + b(i + 5) * 6)) + R * 0.02 * Math.sin(th + i * 0.5);
        g.lineTo(C + ox + r * Math.cos(th), C + oy + 0.86 * r * Math.sin(th) + R * 0.02);
      }
      g.stroke();
    }
  }
  return g.getImageData(0, 0, S, S).data;
}

// a 2D canvas that works where OffscreenCanvas does not
function OffscreenCanvasLike(w, h) {
  const c = typeof OffscreenCanvas !== 'undefined' ? new OffscreenCanvas(w, h) : Object.assign(document.createElement('canvas'), { width: w, height: h });
  return { canvas: c, ctx: c.getContext('2d', { willReadFrequently: true }) };
}

function boxBlur(src, r) {
  const out = new Float32Array(src.length), tmp = new Float32Array(src.length), d = 2 * r + 1;
  for (let y = 0; y < S; y++) {
    let acc = 0; for (let x = -r; x <= r; x++) acc += src[y * S + Math.min(S - 1, Math.max(0, x))];
    for (let x = 0; x < S; x++) { tmp[y * S + x] = acc / d; acc += src[y * S + Math.min(S - 1, x + r + 1)] - src[y * S + Math.max(0, x - r)]; }
  }
  for (let x = 0; x < S; x++) {
    let acc = 0; for (let y = -r; y <= r; y++) acc += tmp[Math.min(S - 1, Math.max(0, y)) * S + x];
    for (let y = 0; y < S; y++) { out[y * S + x] = acc / d; acc += tmp[Math.min(S - 1, y + r + 1) * S + x] - tmp[Math.max(0, y - r) * S + x]; }
  }
  return out;
}

/** Prepare an impression; returns {draw(t)} where t in 0..1 is how deep it is pressed. */
export function impression(canvas, { kind, bytes, ring }) {
  canvas.width = S; canvas.height = S;
  const ctx = canvas.getContext('2d');
  const raw = heightMap(kind, bytes, ring);
  let h = new Float32Array(S * S);
  for (let i = 0; i < S * S; i++) h[i] = raw[i * 4] / 255;
  h = boxBlur(boxBlur(h, 2), 1);
  const L = [-0.55, -0.62, 0.56], ln = Math.hypot(...L); L[0] /= ln; L[1] /= ln; L[2] /= ln;
  const hi = new Float32Array(S * S), lo = new Float32Array(S * S), K = 3.2;
  for (let y = 1; y < S - 1; y++) for (let x = 1; x < S - 1; x++) {
    const i = y * S + x;
    const dx = h[i + 1] - h[i - 1], dy = h[i + S] - h[i - S];
    let nx = -dx * K, ny = -dy * K, nz = 1; const n = Math.hypot(nx, ny, nz); nx /= n; ny /= n; nz /= n;
    const s = nx * L[0] + ny * L[1] + nz * L[2] - L[2];
    // soft edge of the field
    const rx = (x - S / 2) / (S / 2), ry = (y - S / 2) / (S / 2), rr = Math.hypot(rx, ry), edge = Math.min(1, Math.max(0, (1 - rr) / 0.03));
    if (s > 0) hi[i] = Math.min(1, s * 2.1) * edge; else lo[i] = Math.min(1, -s * 2.3) * edge;
    lo[i] += h[i] * 0.10 * edge; // the raised design catches a little less of the wax's inner glow
  }
  const img = ctx.createImageData(S, S), px = img.data;
  return {
    draw(t) {
      const k = Math.max(0, Math.min(1, t));
      for (let i = 0; i < S * S; i++) {
        const a = hi[i] * 0.95, b = lo[i] * 0.9, o = i * 4;
        if (a >= b) { px[o] = 214; px[o + 1] = 248; px[o + 2] = 222; px[o + 3] = a * 255 * k; }
        else { px[o] = 2; px[o + 1] = 16; px[o + 2] = 10; px[o + 3] = b * 255 * k; }
      }
      ctx.putImageData(img, 0, 0);
    },
  };
}

/** animate a press: quick in, a small overshoot, settle */
export function press(imp, ms = 720, reduced = false) {
  if (reduced) { imp.draw(1); return Promise.resolve(); }
  return new Promise((done) => {
    const t0 = performance.now();
    const step = (now) => {
      const u = Math.min(1, (now - t0) / ms);
      const e = u < 0.55 ? (u / 0.55) ** 2 * 1.12 : 1.12 - 0.12 * Math.sin(((u - 0.55) / 0.45) * Math.PI / 2);
      imp.draw(e);
      if (u < 1) requestAnimationFrame(step); else { imp.draw(1); done(); }
    };
    requestAnimationFrame(step);
  });
}
