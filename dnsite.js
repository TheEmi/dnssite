#!/usr/bin/env node
/**
 * Host a website in DNS TXT records (linked-list fragments).
 *
 * Record format (one TXT RRset per node):
 *   dnsite2|<enc>|next=<fqdn>|<chunk>
 *   dnsite2|<enc>|end|<chunk>
 *
 * <enc> is:
 *   gzb64  — payload is gzip(html) then base64, split across the chain
 *   raw    — payload is plain UTF-8 HTML split across the chain
 *
 * Legacy dnsite1|next=…| / dnsite1|end|… is treated as raw.
 *
 * Each fragment is sized so the full TXT value stays under ~200 bytes
 * (many providers cap a single character-string at 255 octets). Adjacent
 * character-strings in one RRset are concatenated (RFC 1035).
 */

import { promises as dns } from "node:dns";
import { readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { parseArgs } from "node:util";
import { gunzipSync, gzipSync } from "node:zlib";

const VERSION = "dnsite2";
const MAX_CHUNK = 200;
const ENC_GZB64 = "gzb64";
const ENC_RAW = "raw";

// dnsite2|enc|next=fqdn|body  OR  dnsite2|enc|end|body
const HEADER_RE = new RegExp(
  `^${VERSION}\\|(?<enc>[a-z0-9]+)\\|(?:next=(?<next>[^|]+)|(?<end>end))\\|(?<body>.*)$`,
  "s",
);
// legacy: dnsite1|next=fqdn|body  OR  dnsite1|end|body
const LEGACY_RE = /^dnsite1\|(?:next=(?<next>[^|]+)|(?<end>end))\|(?<body>.*)$/s;

function txtChunksToString(chunks) {
  // Node returns string[][] — each inner array is character-strings of one RDATA.
  return chunks.map((parts) => parts.join(""));
}

async function lookupTxt(name, resolver) {
  let records;
  try {
    records = resolver
      ? await resolver.resolveTxt(name)
      : await dns.resolveTxt(name);
  } catch (err) {
    const code = err?.code;
    if (code === "ENOTFOUND" || code === "ENODATA") {
      throw new Error(`No TXT records at ${name} (${code})`);
    }
    throw new Error(`DNS error for ${name}: ${err.message}`);
  }

  const candidates = txtChunksToString(records);
  for (const text of candidates) {
    if (text.startsWith("dnsite2|") || text.startsWith("dnsite1|")) return text;
  }
  return candidates.join("");
}

function parseFragment(raw) {
  let m = HEADER_RE.exec(raw);
  if (m) {
    return {
      enc: m.groups.enc,
      next: nextFromMatch(m),
      body: m.groups.body,
    };
  }
  m = LEGACY_RE.exec(raw);
  if (m) {
    return { enc: ENC_RAW, next: nextFromMatch(m), body: m.groups.body };
  }
  throw new Error(
    `Bad fragment (expected ${VERSION}|${ENC_GZB64}|next=<fqdn>|…):\n${JSON.stringify(raw.slice(0, 120))}`,
  );
}

function nextFromMatch(m) {
  if (m.groups.end != null) return null;
  const nxt = m.groups.next.trim();
  if (nxt === "." || nxt === "" || nxt === "end") return null;
  return nxt;
}

function decodePayload(assembled, enc) {
  if (enc === ENC_RAW || enc === "plain") return assembled;
  if (enc === ENC_GZB64) {
    try {
      const buf = Buffer.from(assembled, "base64");
      return gunzipSync(buf).toString("utf8");
    } catch (err) {
      throw new Error(`Failed to decode gzb64 payload: ${err.message}`);
    }
  }
  throw new Error(`Unknown payload encoding: ${enc}`);
}

async function followChain(entry, getTxt, { maxHops = 256 } = {}) {
  const parts = [];
  const seen = new Set();
  let name = entry.replace(/\.$/, "");
  let enc = null;

  for (let hop = 0; hop < maxHops; hop++) {
    const key = name.toLowerCase();
    if (seen.has(key)) throw new Error(`Cycle detected at ${name}`);
    seen.add(key);

    const frag = parseFragment(await getTxt(name));
    if (enc == null) enc = frag.enc;
    else if (frag.enc !== enc) {
      throw new Error(`Encoding changed mid-chain at ${name}: ${enc} → ${frag.enc}`);
    }
    parts.push(frag.body);
    if (frag.next == null) return decodePayload(parts.join(""), enc);
    name = frag.next.replace(/\.$/, "");
  }
  throw new Error(`Exceeded ${maxHops} fragments (possible loop)`);
}

async function fetchSite(entry, { nameservers, timeout = 5000, maxHops = 256 } = {}) {
  let resolver = null;
  if (nameservers?.length) {
    resolver = new dns.Resolver();
    resolver.setServers(nameservers);
  }

  const getTxt = async (name) => {
    if (!timeout) return lookupTxt(name, resolver);
    return Promise.race([
      lookupTxt(name, resolver),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Timeout resolving ${name}`)), timeout),
      ),
    ]);
  };

  return followChain(entry, getTxt, { maxHops });
}

function fetchSiteFromMap(entry, records, { maxHops = 256 } = {}) {
  const getTxt = async (name) => {
    const key = name.replace(/\.$/, "").toLowerCase();
    for (const [k, v] of Object.entries(records)) {
      if (k.replace(/\.$/, "").toLowerCase() === key) return v;
    }
    throw new Error(`No TXT in map for ${name}`);
  };
  return followChain(entry, getTxt, { maxHops });
}

function encodeFragment(enc, body, nextName) {
  if (nextName) return `${VERSION}|${enc}|next=${nextName}|${body}`;
  return `${VERSION}|${enc}|end|${body}`;
}

function chunkUtf8(text, size) {
  const data = Buffer.from(text, "utf8");
  const chunks = [];
  let i = 0;
  while (i < data.length) {
    let j = Math.min(i + size, data.length);
    // Don't split a multibyte UTF-8 sequence.
    while (j > i && j < data.length && (data[j] & 0xc0) === 0x80) j--;
    if (j === i) j = Math.min(i + size, data.length);
    chunks.push(data.subarray(i, j).toString("utf8"));
    i = j;
  }
  return chunks.length ? chunks : [""];
}

function preparePayload(htmlText, { compress = true } = {}) {
  if (!compress) {
    return { enc: ENC_RAW, payload: htmlText, rawBytes: Buffer.byteLength(htmlText), wireBytes: Buffer.byteLength(htmlText) };
  }
  const gz = gzipSync(Buffer.from(htmlText, "utf8"), { level: 9 });
  const payload = gz.toString("base64");
  return {
    enc: ENC_GZB64,
    payload,
    rawBytes: Buffer.byteLength(htmlText),
    wireBytes: Buffer.byteLength(payload),
    gzBytes: gz.length,
  };
}

function fragmentHtml(htmlText, baseName, { chunkSize = MAX_CHUNK, compress = true } = {}) {
  const base = baseName.replace(/\.$/, "");
  const prepared = preparePayload(htmlText, { compress });
  const overhead = Buffer.byteLength(
    `${VERSION}|${prepared.enc}|next=p999.${base}|`,
    "utf8",
  );
  const bodyBudget = Math.max(32, chunkSize - overhead);
  const chunks = chunkUtf8(prepared.payload, bodyBudget);

  const records = chunks.map((chunk, idx) => {
    const name = idx === 0 ? base : `p${idx}.${base}`;
    const next = idx === chunks.length - 1 ? null : `p${idx + 1}.${base}`;
    return [name, encodeFragment(prepared.enc, chunk, next)];
  });

  return { records, meta: { ...prepared, fragments: records.length } };
}

function escapeTxtZone(value) {
  // BIND master-file escapes: \X (non-digit) → literal X, so "\n" becomes "n".
  // Newline/tab/CR must use decimal byte escapes: \010 \009 \013.
  const raw = Buffer.from(value, "utf8");
  const parts = [];
  for (let i = 0; i < raw.length; i += 255) {
    const slice = raw.subarray(i, i + 255);
    let s = "";
    for (const byte of slice) {
      if (byte === 0x22) s += '\\"'; // "
      else if (byte === 0x5c) s += "\\\\"; // \
      else if (byte === 0x0a) s += "\\010"; // newline
      else if (byte === 0x0d) s += "\\013"; // CR
      else if (byte === 0x09) s += "\\009"; // tab
      else if (byte < 0x20 || byte === 0x7f) {
        s += `\\${String(byte).padStart(3, "0")}`;
      } else {
        s += String.fromCharCode(byte);
      }
    }
    parts.push(`"${s}"`);
  }
  return parts.join(" ");
}

function renderErrorPage(message) {
  const esc = message
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
  return `<!DOCTYPE html><html><head><meta charset=utf-8><title>DNSite error</title></head><body><h1>DNSite</h1><pre>${esc}</pre></body></html>`;
}

function openBrowser(filePath) {
  const url = pathToFileURL(filePath).href;
  const platform = process.platform;
  const cmd =
    platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open";
  const args = platform === "win32" ? ["/c", "start", "", url] : [url];
  spawn(cmd, args, { detached: true, stdio: "ignore" }).unref();
  console.error(`Opened ${filePath}`);
}

function emitPage(page, { output, open }) {
  if (output) {
    writeFileSync(output, page, "utf8");
    console.error(`Wrote ${output} (${Buffer.byteLength(page, "utf8")} bytes)`);
  } else if (!open) {
    process.stdout.write(page);
  }

  if (open) {
    let path = output;
    if (!path) {
      path = join(tmpdir(), `dnsite-${Date.now()}.html`);
      writeFileSync(path, page, "utf8");
    }
    openBrowser(path);
  }
}

function formatRecords(records, format, meta = {}) {
  if (format === "json") {
    return `${JSON.stringify(Object.fromEntries(records), null, 2)}\n`;
  }

  const lines = [];
  if (format === "bind") {
    lines.push("; DNSite TXT fragments — $INCLUDE or paste into your zone");
    lines.push(`; Entry point: ${records[0]?.[0] ?? "?"}`);
    lines.push(`; Fragments: ${records.length}`);
    lines.push(`; Encoding: ${meta.enc ?? "?"}`);
    if (meta.rawBytes != null && meta.wireBytes != null) {
      lines.push(
        `; HTML ${meta.rawBytes}B → wire ${meta.wireBytes}B` +
          (meta.gzBytes != null ? ` (gzip ${meta.gzBytes}B)` : ""),
      );
    }
    lines.push("$TTL 300");
    lines.push("");
    for (const [name, value] of records) {
      lines.push(`${name}.  IN  TXT  ${escapeTxtZone(value)}`);
    }
    lines.push("");
    return `${lines.join("\n")}`;
  }

  if (format === "cloudflare") {
    for (const [name, value] of records) {
      const esc = value
        .replaceAll("\\", "\\\\")
        .replaceAll('"', '\\"')
        .replaceAll("\n", "\\n")
        .replaceAll("\r", "\\r");
      lines.push(`${name}.  TXT  "${esc}"`);
    }
    return `${lines.join("\n")}\n`;
  }

  throw new Error(`Unknown --format ${format}`);
}

function defaultBindPath(baseName) {
  return `${baseName.replace(/\.$/, "")}.bind`;
}

function usage(exit = 1) {
  console.error(`Usage:
  dnsite fragment <html-file> <base-fqdn> [-o file] [--chunk N] [--raw]
                 [--format bind|cloudflare|json]
  dnsite get <entry-fqdn> [-o file] [--open] [--ns IP]... [--timeout ms] [--map file.json]

  fragment gzip+base64-compresses by default, then writes a BIND zone snippet
  (<base-fqdn>.bind). Use --raw to skip compression. Use -o - for stdout.`);
  process.exit(exit);
}

async function main() {
  const argv = process.argv.slice(2);
  const cmd = argv[0];
  if (!cmd || cmd === "-h" || cmd === "--help") usage(cmd ? 0 : 1);

  if (cmd === "fragment") {
    const { values, positionals } = parseArgs({
      args: argv.slice(1),
      allowPositionals: true,
      options: {
        output: { type: "string", short: "o" },
        chunk: { type: "string", default: String(MAX_CHUNK) },
        format: { type: "string", default: "bind" },
        raw: { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
    if (values.help || positionals.length < 2) usage(values.help ? 0 : 1);

    const [htmlFile, baseName] = positionals;
    const text = readFileSync(htmlFile, "utf8");
    const { records, meta } = fragmentHtml(text, baseName, {
      chunkSize: Number(values.chunk) || MAX_CHUNK,
      compress: !values.raw,
    });

    let body;
    try {
      body = formatRecords(records, values.format, meta);
    } catch (err) {
      console.error(err.message);
      usage();
    }

    const toStdout = values.output === "-";
    const outPath =
      values.output && !toStdout
        ? values.output
        : values.format === "bind" && !toStdout
          ? defaultBindPath(baseName)
          : null;

    const summary =
      `${records.length} fragment(s); enc=${meta.enc}; ` +
      `${meta.rawBytes}B html → ${meta.wireBytes}B wire` +
      (meta.gzBytes != null ? ` (gzip ${meta.gzBytes}B)` : "");

    if (outPath) {
      writeFileSync(outPath, body, "utf8");
      console.error(`Wrote ${outPath} (${summary})`);
    } else {
      process.stdout.write(body);
      console.error(`# ${summary}; entry point: ${baseName}`);
    }
    return;
  }

  if (cmd === "get") {
    const { values, positionals } = parseArgs({
      args: argv.slice(1),
      allowPositionals: true,
      options: {
        output: { type: "string", short: "o" },
        open: { type: "boolean", default: false },
        ns: { type: "string", multiple: true, default: [] },
        timeout: { type: "string", default: "5000" },
        map: { type: "string" },
        help: { type: "boolean", short: "h", default: false },
      },
    });
    if (values.help || positionals.length < 1) usage(values.help ? 0 : 1);

    const entry = positionals[0];
    let page;
    try {
      if (values.map) {
        const records = JSON.parse(readFileSync(values.map, "utf8"));
        page = await fetchSiteFromMap(entry, records);
      } else {
        page = await fetchSite(entry, {
          nameservers: values.ns,
          timeout: Number(values.timeout) || 5000,
        });
      }
    } catch (err) {
      console.error(`error: ${err.message}`);
      page = renderErrorPage(err.message);
      if (!values.output && !values.open) process.exit(1);
      emitPage(page, { output: values.output, open: values.open });
      process.exit(1);
    }

    emitPage(page, { output: values.output, open: values.open });
    return;
  }

  usage();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
