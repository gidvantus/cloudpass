#!/usr/bin/env node
// Generates the application icon from the portal's favicon.
//
// The mark is defined once, in `apps/web/ui/favicon.svg`: a black square, a hairline white
// square inset from its edges, and a white dot in the middle. That file is what a browser tab
// shows. This script draws the same geometry into the Windows `.ico` that Tauri embeds into
// the executable and the installer, so the tab and the installed application carry one mark
// rather than two similar ones.
//
// It is generated rather than committed as a binary blob because the shape has four numbers
// and they are all in the SVG. Change the SVG, run this, and the icon follows.
//
// The icon holds every size Windows asks for: 16 and 20 in a list, 32 in the taskbar, 48 in
// Explorer, 256 in the jumbo view. A single 32x32 would be scaled up by Explorer for the large
// views and the hairline would blur into grey, so each size is drawn from the geometry rather
// than resampled from a smaller one.
//
// Usage: node scripts/make-app-icon.mjs

import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..')
const outputDir = join(repoRoot, 'apps', 'desktop', 'icons')
const outputPath = join(outputDir, 'icon.ico')

// The favicon's own coordinate system, and the four numbers that describe the mark:
// `<rect width="32" height="32" fill="#000000">` is the background,
// `<rect x="5" y="5" width="22" height="22" stroke-width="1.5">` is the hairline, and
// `<circle cx="16" cy="16" r="3.5">` is the dot. Keep these in step with that file.
const VIEWBOX = 32
const EDGE = 5
const SPAN = 22
const STROKE = 1.5
const DOT_RADIUS = 3.5

/// What Windows actually renders, smallest first.
const SIZES = [16, 24, 32, 48, 64, 128, 256]

/// Subpixels per axis. Four is enough for a 1.5-unit hairline at 16px — the thinnest case
/// here — and keeps the whole script instant.
const SAMPLES = 4

/**
 * Whether a point in the favicon's coordinates is part of the white mark.
 *
 * The stroked square is `outer minus inner`: a square stroke with miter joins covers the band
 * between the path and the path offset by half the width on every side, so that subtraction
 * is exact rather than an approximation of it.
 */
function isMark(x, y) {
  const half = STROKE / 2
  const outerLow = EDGE - half
  const outerHigh = EDGE + SPAN + half
  const innerLow = EDGE + half
  const innerHigh = EDGE + SPAN - half

  const inOuter = x >= outerLow && x <= outerHigh && y >= outerLow && y <= outerHigh
  const inInner = x >= innerLow && x <= innerHigh && y >= innerLow && y <= innerHigh
  if (inOuter && !inInner) return true

  const dx = x - VIEWBOX / 2
  const dy = y - VIEWBOX / 2
  return dx * dx + dy * dy <= DOT_RADIUS * DOT_RADIUS
}

/**
 * Renders one size as bottom-up BGRA, which is what a BMP inside an `.ico` holds.
 *
 * The background stays opaque: the favicon is a filled black square rather than a mark on
 * transparency, so the icon is the same square and reads the same on a light taskbar and a
 * dark one.
 */
function render(size) {
  const pixels = Buffer.alloc(size * size * 4)
  const step = VIEWBOX / size
  const samples = SAMPLES * SAMPLES

  for (let row = 0; row < size; row++) {
    // Row 0 is the bottom of the image; the source row counts from the top.
    const top = size - 1 - row
    for (let column = 0; column < size; column++) {
      let hits = 0
      for (let sy = 0; sy < SAMPLES; sy++) {
        for (let sx = 0; sx < SAMPLES; sx++) {
          const x = (column + (sx + 0.5) / SAMPLES) * step
          const y = (top + (sy + 0.5) / SAMPLES) * step
          if (isMark(x, y)) hits++
        }
      }

      const level = Math.round((255 * hits) / samples)
      const offset = (row * size + column) * 4
      pixels[offset] = level // blue
      pixels[offset + 1] = level // green
      pixels[offset + 2] = level // red
      pixels[offset + 3] = 0xff // opaque
    }
  }

  return pixels
}

/// Wraps BGRA pixels in the BITMAPINFOHEADER and AND mask an `.ico` image is made of.
function bitmap(size, pixels) {
  const header = Buffer.alloc(40)
  header.writeUInt32LE(40, 0) // header size
  header.writeInt32LE(size, 4) // width
  header.writeInt32LE(size * 2, 8) // height: XOR + AND
  header.writeUInt16LE(1, 12) // planes
  header.writeUInt16LE(32, 14) // bits per pixel
  header.writeUInt32LE(0, 16) // BI_RGB
  header.writeUInt32LE(size * size * 4, 20) // XOR payload size

  // The AND mask is all zeroes: the alpha channel already carries the shape, and every
  // renderer this icon reaches honours it.
  const stride = Math.ceil(size / 32) * 4
  const mask = Buffer.alloc(stride * size)

  return Buffer.concat([header, pixels, mask])
}

const images = SIZES.map((size) => ({ size, bytes: bitmap(size, render(size)) }))

const directory = Buffer.alloc(6)
directory.writeUInt16LE(0, 0) // reserved
directory.writeUInt16LE(1, 2) // type: icon
directory.writeUInt16LE(images.length, 4)

let offset = directory.length + images.length * 16
const entries = images.map(({ size, bytes }) => {
  const entry = Buffer.alloc(16)
  // 256 is written as 0: the field is a byte, and 256 does not fit in one. That is the format,
  // not a truncation.
  entry.writeUInt8(size >= 256 ? 0 : size, 0)
  entry.writeUInt8(size >= 256 ? 0 : size, 1)
  entry.writeUInt8(0, 2) // palette size
  entry.writeUInt8(0, 3) // reserved
  entry.writeUInt16LE(1, 4) // colour planes
  entry.writeUInt16LE(32, 6) // bits per pixel
  entry.writeUInt32LE(bytes.length, 8)
  entry.writeUInt32LE(offset, 12)
  offset += bytes.length
  return entry
})

const ico = Buffer.concat([directory, ...entries, ...images.map((image) => image.bytes)])

mkdirSync(outputDir, { recursive: true })
writeFileSync(outputPath, ico)
console.log(
  `wrote ${outputPath} (${ico.length} bytes, ${SIZES.join('/')} in one icon)`,
)
