// Renders app-icon.png (1024x1024): rounded square, globe ring, egress check mark.
import { writeFileSync } from "node:fs";
import { deflateSync } from "node:zlib";

const S = 1024;
const px = Buffer.alloc(S * S * 4);

const smooth = (d) => Math.max(0, Math.min(1, 0.5 - d));
function blend(i, [r, g, b], a) {
  if (a <= 0) return;
  const ia = 1 - a;
  px[i] = px[i] * ia + r * a;
  px[i + 1] = px[i + 1] * ia + g * a;
  px[i + 2] = px[i + 2] * ia + b * a;
  px[i + 3] = Math.min(255, px[i + 3] + 255 * a);
}
function segDist(x, y, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(x - ax - t * dx, y - ay - t * dy);
}

const bg = [30, 64, 175], ring = [255, 255, 255], ok = [34, 197, 94];
const c = S / 2, R = 300, W = 44;
for (let y = 0; y < S; y++) {
  for (let x = 0; x < S; x++) {
    const i = (y * S + x) * 4;
    const m = 72, rr = 200;
    const qx = Math.max(Math.abs(x + 0.5 - c) - (c - m - rr), 0);
    const qy = Math.max(Math.abs(y + 0.5 - c) - (c - m - rr), 0);
    blend(i, bg, smooth(Math.hypot(qx, qy) - rr));

    const d = Math.hypot(x + 0.5 - c, y + 0.5 - c);
    blend(i, ring, smooth(Math.abs(d - R) - W / 2));
    const ex = Math.abs(x + 0.5 - c) / 120, ey = (y + 0.5 - c) / R;
    if (Math.abs(ey) < 1) blend(i, ring, smooth((Math.abs(Math.hypot(ex, ey) - 1) * 120) - W / 2.6));
    if (d < R) blend(i, ring, smooth(Math.abs(y + 0.5 - c) - W / 2.6));

    const cx = 700, cy = 700, cr = 170;
    const dc = Math.hypot(x + 0.5 - cx, y + 0.5 - cy);
    blend(i, bg, smooth(dc - cr - 26));
    blend(i, ok, smooth(dc - cr));
    const ck = Math.min(segDist(x + 0.5, y + 0.5, 620, 705, 680, 765), segDist(x + 0.5, y + 0.5, 680, 765, 790, 640));
    blend(i, ring, smooth(ck - 22));
  }
}

const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type), data]);
  const cr = Buffer.alloc(4);
  cr.writeUInt32BE(crc(td));
  return Buffer.concat([len, td, cr]);
};
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(S, 0);
ihdr.writeUInt32BE(S, 4);
ihdr[8] = 8;
ihdr[9] = 6;
const raw = Buffer.alloc(S * (S * 4 + 1));
for (let y = 0; y < S; y++) px.copy(raw, y * (S * 4 + 1) + 1, y * S * 4, (y + 1) * S * 4);
writeFileSync(
  "app-icon.png",
  Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]),
);
console.log("wrote app-icon.png");
