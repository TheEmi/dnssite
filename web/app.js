const VERSION2 = "dnsite2";
const HEADER_RE = new RegExp(
  `^${VERSION2}\\|(?<enc>[a-z0-9]+)\\|(?:next=(?<next>[^|]+)|(?<end>end))\\|(?<body>.*)$`,
  "s",
);
const LEGACY_RE = /^dnsite1\|(?:next=(?<next>[^|]+)|(?<end>end))\|(?<body>.*)$/s;

const DOH_ENDPOINTS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
];

const app = document.querySelector(".app");
const form = document.getElementById("lookup");
const hostInput = document.getElementById("host");
const statusEl = document.getElementById("status");
const frame = document.getElementById("frame");
const stage = document.getElementById("stage");
const empty = document.getElementById("empty");
const submitBtn = document.getElementById("submit");
const minimizeBtn = document.getElementById("minimize");
const expandBtn = document.getElementById("expand");
const peekHost = document.getElementById("peek-host");

function setStatus(message, tone = "") {
  statusEl.textContent = message;
  statusEl.dataset.tone = tone;
}

function setChromeMinimized(min) {
  app.classList.toggle("chrome-min", min);
  minimizeBtn.setAttribute("aria-expanded", String(!min));
  expandBtn.hidden = !min;
  expandBtn.setAttribute("aria-expanded", String(min));
  peekHost.textContent = hostInput.value.trim() || defaultHost();
}

function minimizeChrome() {
  setChromeMinimized(true);
}

function expandChrome() {
  setChromeMinimized(false);
  hostInput.focus();
}

function normalizeHost(value) {
  let host = String(value || "").trim();
  if (!host) return "";
  // Allow pasting https://viewer/?host=… by mistake, or bare URLs.
  try {
    if (/^https?:\/\//i.test(host)) {
      const u = new URL(host);
      host = u.searchParams.get("host") || u.searchParams.get("q") || u.hostname;
    }
  } catch {
    /* keep raw */
  }
  return host.replace(/\.$/, "").replace(/^\/+/, "");
}

function nextFromMatch(m) {
  if (m.groups.end != null) return null;
  const nxt = m.groups.next.trim();
  if (nxt === "." || nxt === "" || nxt === "end") return null;
  return nxt;
}

function parseFragment(raw) {
  let m = HEADER_RE.exec(raw);
  if (m) {
    return { enc: m.groups.enc, next: nextFromMatch(m), body: m.groups.body };
  }
  m = LEGACY_RE.exec(raw);
  if (m) {
    return { enc: "raw", next: nextFromMatch(m), body: m.groups.body };
  }
  throw new Error(`Not a DNSite TXT record: ${JSON.stringify(raw.slice(0, 100))}`);
}

function unwrapTxtData(data) {
  // DoH often returns: "\"part1\" \"part2\"" or "part1"
  const chunks = [];
  const re = /"((?:\\.|[^"\\])*)"|([^\s"]+)/g;
  let match;
  while ((match = re.exec(data)) !== null) {
    const part = match[1] != null ? match[1] : match[2];
    chunks.push(
      part
        .replace(/\\"/g, '"')
        .replace(/\\010/g, "\n")
        .replace(/\\013/g, "\r")
        .replace(/\\009/g, "\t")
        .replace(/\\([0-9]{3})/g, (_, n) => String.fromCharCode(Number(n)))
        .replace(/\\(.)/g, "$1"),
    );
  }
  return chunks.join("") || data;
}

async function resolveTxt(name, { signal } = {}) {
  let lastErr;
  for (const endpoint of DOH_ENDPOINTS) {
    try {
      const url = new URL(endpoint);
      url.searchParams.set("name", name);
      url.searchParams.set("type", "TXT");
      const res = await fetch(url, {
        headers: { Accept: "application/dns-json" },
        signal,
      });
      if (!res.ok) throw new Error(`DoH HTTP ${res.status} from ${url.host}`);
      const json = await res.json();
      if (json.Status !== 0 || !json.Answer?.length) {
        throw new Error(`No TXT answer for ${name}`);
      }
      const txts = json.Answer.filter((a) => a.type === 16).map((a) =>
        unwrapTxtData(String(a.data)),
      );
      if (!txts.length) throw new Error(`No TXT answer for ${name}`);
      const preferred =
        txts.find((t) => t.startsWith("dnsite2|") || t.startsWith("dnsite1|")) ||
        txts.join("");
      return preferred;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr ?? new Error(`DNS lookup failed for ${name}`);
}

async function gunzipBase64(b64) {
  const bin = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  if (typeof DecompressionStream === "undefined") {
    throw new Error("This browser cannot gunzip (no DecompressionStream)");
  }
  const stream = new Blob([bin]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Response(stream).text();
}

async function decodePayload(assembled, enc) {
  if (enc === "raw" || enc === "plain") return assembled;
  if (enc === "gzb64") return gunzipBase64(assembled);
  throw new Error(`Unknown encoding: ${enc}`);
}

async function fetchSite(entry, { onProgress, signal } = {}) {
  const parts = [];
  const seen = new Set();
  let name = normalizeHost(entry);
  let enc = null;
  let hops = 0;

  while (hops < 256) {
    const key = name.toLowerCase();
    if (seen.has(key)) throw new Error(`Cycle detected at ${name}`);
    seen.add(key);
    hops += 1;
    onProgress?.(`Resolving ${name}… (${hops})`);

    const frag = parseFragment(await resolveTxt(name, { signal }));
    if (enc == null) enc = frag.enc;
    else if (frag.enc !== enc) {
      throw new Error(`Encoding changed at ${name}: ${enc} → ${frag.enc}`);
    }
    parts.push(frag.body);
    if (frag.next == null) {
      onProgress?.(`Decoding ${parts.length} fragment(s)…`);
      return {
        html: await decodePayload(parts.join(""), enc),
        hops,
        enc,
        entry: normalizeHost(entry),
      };
    }
    name = frag.next.replace(/\.$/, "");
  }
  throw new Error("Exceeded 256 fragments (possible loop)");
}

function renderPage(html) {
  frame.removeAttribute("src");
  frame.srcdoc = html;
  stage.classList.add("is-loaded");
  empty.hidden = true;
}

function clearPage() {
  frame.srcdoc = "";
  stage.classList.remove("is-loaded");
  empty.hidden = false;
}

function syncUrl(host, { replace = false } = {}) {
  const url = new URL(window.location.href);
  // Keep the address bar clean when viewing this host’s own TXT site.
  if (host && normalizeHost(host) !== normalizeHost(defaultHost())) {
    url.searchParams.set("host", host);
  } else {
    url.searchParams.delete("host");
  }
  url.searchParams.delete("q");
  url.hash = "";
  const next = `${url.pathname}${url.search}`;
  if (replace) history.replaceState(null, "", next);
  else history.pushState(null, "", next);
}

let activeAbort = null;

async function loadHost(rawHost, { push = true } = {}) {
  const host = normalizeHost(rawHost);
  if (!host) {
    setStatus("Enter a DNSite entry name, e.g. site.example.com", "error");
    return;
  }

  activeAbort?.abort();
  const ac = new AbortController();
  activeAbort = ac;

  hostInput.value = host;
  if (push) syncUrl(host);
  else syncUrl(host, { replace: true });

  submitBtn.disabled = true;
  expandChrome();
  clearPage();
  setStatus(`Looking up ${host}…`);

  try {
    const result = await fetchSite(host, {
      signal: ac.signal,
      onProgress: (msg) => setStatus(msg),
    });
    renderPage(result.html);
    setStatus(
      `Loaded ${result.entry} · ${result.hops} fragment(s) · ${result.enc}`,
      "ok",
    );
    minimizeChrome();
  } catch (err) {
    if (err?.name === "AbortError") return;
    clearPage();
    expandChrome();
    setStatus(err.message || String(err), "error");
  } finally {
    submitBtn.disabled = false;
  }
}

function isLocalHost(host) {
  const h = String(host || "").toLowerCase();
  return (
    !h ||
    h === "localhost" ||
    h === "127.0.0.1" ||
    h === "[::1]" ||
    h.endsWith(".localhost")
  );
}

function defaultHost() {
  return window.location.hostname || "";
}

function hostFromLocation() {
  const url = new URL(window.location.href);
  const fromQuery =
    url.searchParams.get("host") ||
    url.searchParams.get("q") ||
    (url.hash.startsWith("#") ? decodeURIComponent(url.hash.slice(1)) : "");
  if (fromQuery) return fromQuery;
  return defaultHost();
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  loadHost(hostInput.value, { push: true });
});

minimizeBtn.addEventListener("click", () => minimizeChrome());
expandBtn.addEventListener("click", () => expandChrome());

window.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && app.classList.contains("chrome-min")) {
    expandChrome();
  }
});

window.addEventListener("popstate", () => {
  loadHost(hostFromLocation(), { push: false });
});

const initial = hostFromLocation();
hostInput.placeholder = isLocalHost(defaultHost())
  ? "site.example.com"
  : defaultHost();
hostInput.value = normalizeHost(initial);

if (isLocalHost(initial) && !(new URL(window.location.href).searchParams.get("host") || new URL(window.location.href).searchParams.get("q"))) {
  setStatus("Local preview — enter a DNSite hostname, or deploy on the TXT subdomain");
} else {
  loadHost(initial, { push: false });
}
