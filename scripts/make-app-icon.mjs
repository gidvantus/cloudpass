#!/usr/bin/env node
// Generates the placeholder application icon.
//
// Tauri's Windows build embeds an .ico from `bundle.icon`, and a missing file is a
// build error rather than a warning. Rather than committing a binary nobody can
// review, this script writes a deterministic 32x32 icon: a neutral rounded square with
// the CloudPass ring. Replace it with a real design when one exists, and update
// `tauri.conf.json` if the file name changes.
//
// Usage: node scripts/make-app-icon.mjs

import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const outputDir = join(repoRoot, 'apps', 'desktop', 'icons')
const outputPath = join(outputDir, 'icon.ico')

const SIZE = 32

/// Background, ring and highlight colours.
const BACKGROUND = [0x1e, 0x29, 0x3b]
const RING = [0x60, 0xa5, 0xfa]

function pixel(x, y) {
  const cx = (SIZE - 1) / 2
  const cy = (SIZE - 1) / 2
  const distance = Math.hypot(x - cx, y - cy)

  // A ring rather than a filled disc: it reads as a keyhole at 16px without detail.
  if (distance > 12.5) return [0, 0, 0, 0]
  if (distance > 9.0) return [...RING, 0xff]
  // The inner dot of the ring.
  if (distance < 3.0) return [...RING, 0xff]
  return [...BACKGROUND, 0xff]
}

// BITMAPINFOHEADER, then the BGRA pixels bottom-up, then the 1bpp AND mask.
const header = Buffer.alloc(40)
header.writeUInt32LE(40, 0) // header size
header.writeInt32LE(SIZE, 4) // width
header.writeInt32LE(SIZE * 2, 8) // height: XOR + AND
header.writeUInt16LE(1, 12) // planes
header.writeUInt16LE(32, 14) // bits per pixel
header.writeUInt32LE(0, 16) // BI_RGB
header.writeUInt32LE(SIZE * SIZE * 4, 20) // XOR payload size

const xor = Buffer.alloc(SIZE * SIZE * 4)
for (let row = 0; row < SIZE; row++) {
  const y = SIZE - 1 - row // bottom-up
  for (let x = 0; x < SIZE; x++) {
    const [r, g, b, a] = pixel(x, y)
    const offset = (row * SIZE + x) * 4
    xor[offset] = b
    xor[offset + 1] = g
    xor[offset + 2] = r
    xor[offset + 3] = a
  }
}

// The AND mask is all zeroes: the alpha channel already carries transparency, and
// every modern Windows renderer honours it.
const maskStride = Math.ceil(SIZE / 32) * 4
const mask = Buffer.alloc(maskStride * SIZE)

const image = Buffer.concat([header, xor, mask])

const directory = Buffer.alloc(6)
directory.writeUInt16LE(0, 0) // reserved
directory.writeUInt16LE(1, 2) // type: icon
directory.writeUInt16LE(1, 4) // one image

const entry = Buffer.alloc(16)
entry.writeUInt8(SIZE, 0)
entry.writeUInt8(SIZE, 1)
entry.writeUInt8(0, 2) // palette size
entry.writeUInt8(0, 3) // reserved
entry.writeUInt16LE(1, 4) // colour planes
entry.writeUInt16LE(32, 6) // bits per pixel
entry.writeUInt32LE(image.length, 8)
entry.writeUInt32LE(directory.length + entry.length, 12)

mkdirSync(outputDir, { recursive: true })
writeFileSync(outputPath, Buffer.concat([directory, entry, image]))
console.log(`wrote ${outputPath} (${directory.length + entry.length + image.length} bytes)`)
