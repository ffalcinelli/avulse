// The filter playground: the avulse-filter engine compiled to WebAssembly (crates/wasm).

const EXAMPLES = [
  {
    name: "Web traffic leaving the LAN",
    outbound: true,
    filter: `let lan = {10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16}
let web = tcp.port in {80, 443, 8000..8100}

outbound and ip.dst not in $lan and $web`,
  },
  { name: "New TCP connections", filter: "tcp.flags.syn == 1 and tcp.flags.ack == 0" },
  { name: "Symbolic flags", filter: "tcp.flags & syn" },
  { name: "Payload starts with an HTTP method", filter: 'tcp.payload matches "^(GET|POST) "' },
  { name: "Bytes and slices", filter: 'tcp.payload[0:4] == "GET " or udp.payload[2:2] == 01:00' },
  { name: "DNS queries", filter: "udp.dstport == 53" },
  { name: "Any port 443, either direction", filter: "tcp.port == 443" },
  { name: "Neither address is the gateway", filter: "ip.addr != 192.168.1.1" },
  { name: "Wireshark value labels", filter: 'ip.proto == "UDP" or icmp.type == "Echo (ping) request"' },
  { name: "VLAN 100", filter: "vlan.id == 100" },
  { name: "Non-IP frames (ETHERNET layer)", filter: "not ip and not ipv6" },
  { name: "Broadcasts", filter: "eth.dst == ff:ff:ff:ff:ff:ff or eth.dst[0] & 1" },
  { name: "Fragments", filter: "fragment or ip.flags.mf == 1" },
  { name: "Arithmetic", filter: "{tcp.srcport + tcp.dstport} % 2 == 1 and len(tcp.payload) > 0" },
  { name: "Error: a typo", filter: "tcp.prot == 80" },
  { name: "Error: wrong address family", filter: "ip.src == ::1" },
  { name: "Error: needs stream state", filter: "tcp.seq == 1" },
  { name: "Warning: a bare boolean field", filter: "tcp.flags.syn" },
];

const $ = (id) => document.getElementById(id);
const ui = {
  examples: $("pg-examples"),
  share: $("pg-share"),
  filter: $("pg-filter"),
  outbound: $("pg-outbound"),
  iface: $("pg-iface"),
  status: $("pg-status"),
  diagnostics: $("pg-diagnostics"),
  canonical: $("pg-canonical"),
  ir: $("pg-ir"),
  rows: $("pg-sample-rows"),
  fieldSearch: $("pg-field-search"),
  fields: $("pg-fields"),
  hex: $("pg-hex"),
  link: $("pg-link"),
  hexResult: $("pg-hex-result"),
};

let engine = null;
let samples = [];
let lastDiagnostics = [];

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

function setVerdict(el, value) {
  el.className = "verdict";
  if (value === true) {
    el.classList.add("match");
    el.textContent = "match";
  } else if (value === false) {
    el.classList.add("nomatch");
    el.textContent = "no match";
  } else if (typeof value === "string") {
    el.classList.add("error");
    el.textContent = value;
  } else {
    el.textContent = "";
  }
}

function renderSamples() {
  ui.rows.replaceChildren(
    ...samples.map((s, i) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td><span class="verdict" id="pg-verdict-${i}"></span></td>
        <td><span class="name">${escapeHtml(s.name)}</span>
          <span class="summary">${escapeHtml(s.summary)}</span>
          <details><summary>bytes</summary><pre>${escapeHtml(s.hex)}</pre>
            <button type="button" class="small" data-sample="${i}">Edit as your own packet</button>
          </details></td>`;
      return tr;
    }),
  );
  ui.rows.addEventListener("click", (e) => {
    const button = e.target.closest("button[data-sample]");
    if (!button) return;
    ui.hex.value = samples[Number(button.dataset.sample)].hex;
    ui.link.value = "ethernet";
    $("pg-custom").open = true;
    ui.hex.focus();
    runCustom();
  });
}

function renderDiagnostics(diagnostics) {
  lastDiagnostics = diagnostics;
  if (diagnostics.length === 0) {
    ui.diagnostics.hidden = true;
    ui.diagnostics.textContent = "";
    return;
  }
  ui.diagnostics.hidden = false;
  ui.diagnostics.innerHTML = diagnostics
    .map((d) => {
      const text = escapeHtml(d.rendered).replace(/^(error|warning):/, `<span class="${d.level}">$1</span>:`);
      return text;
    })
    .join("\n");
}

function analyze() {
  if (!engine) return;
  const src = ui.filter.value;
  if (src.trim() === "") {
    ui.status.className = "pg-status";
    ui.status.textContent = "Type a filter. `true` matches everything.";
    renderDiagnostics([]);
    ui.canonical.textContent = "";
    ui.ir.textContent = "";
    ui.filter.classList.remove("has-error");
    samples.forEach((_, i) => setVerdict($(`pg-verdict-${i}`), null));
    return;
  }
  const result = engine.analyze(src, ui.outbound.checked, ui.iface.value);
  const errors = result.diagnostics.filter((d) => d.level === "error");
  const warnings = result.diagnostics.length - errors.length;
  renderDiagnostics(result.diagnostics);
  ui.canonical.textContent = result.canonical ?? "(the filter does not parse)";
  ui.ir.textContent = result.ir
    ? result.ir + (result.userSpaceOnly ? "\nnote: `matches` runs in user space only; kernel backends pass these packets up" : "")
    : "(the filter does not compile)";
  ui.filter.classList.toggle("has-error", errors.length > 0);
  if (errors.length > 0) {
    ui.status.className = "pg-status error";
    ui.status.textContent = `Does not compile: ${errors[0].message}`;
    samples.forEach((_, i) => setVerdict($(`pg-verdict-${i}`), null));
  } else {
    const matched = result.verdicts.filter(Boolean).length;
    ui.status.className = warnings ? "pg-status warning" : "pg-status ok";
    ui.status.textContent =
      `Compiles${warnings ? ` with ${warnings} warning${warnings > 1 ? "s" : ""}` : ""}. ` +
      `Matches ${matched} of ${samples.length} sample packets.`;
    result.verdicts.forEach((v, i) => setVerdict($(`pg-verdict-${i}`), v));
  }
  runCustom();
}

function runCustom() {
  if (!engine) return;
  const hex = ui.hex.value.trim();
  if (hex === "") {
    setVerdict(ui.hexResult, null);
    return;
  }
  const result = engine.evalHex(ui.filter.value, hex, ui.link.value === "ip", ui.outbound.checked, ui.iface.value);
  setVerdict(ui.hexResult, result);
}

function renderFields(all) {
  const query = ui.fieldSearch.value.trim().toLowerCase();
  const shown = all.filter((f) => !query || f.name.includes(query) || f.desc.toLowerCase().includes(query));
  ui.fields.replaceChildren(
    ...shown.map((f) => {
      const li = document.createElement("li");
      li.innerHTML = `<button type="button" title="Insert into the filter">${escapeHtml(f.name)}</button>
        <span>${escapeHtml(f.desc)} (${escapeHtml(f.ty)}${f.extension ? ", Avulse extension" : ""})</span>`;
      li.querySelector("button").addEventListener("click", () => insertAtCursor(f.name));
      return li;
    }),
  );
}

function insertAtCursor(text) {
  const { selectionStart: start, selectionEnd: end, value } = ui.filter;
  ui.filter.value = value.slice(0, start) + text + value.slice(end);
  ui.filter.focus();
  ui.filter.setSelectionRange(start + text.length, start + text.length);
  analyze();
}

function loadExample(i) {
  const ex = EXAMPLES[i];
  ui.filter.value = ex.filter;
  ui.outbound.checked = ex.outbound ?? ui.outbound.checked;
  analyze();
}

function initialFilter() {
  const params = new URLSearchParams(location.search);
  if (params.has("f")) {
    ui.filter.value = params.get("f");
    ui.outbound.checked = params.get("out") !== "0";
    if (params.has("iface")) ui.iface.value = params.get("iface");
    return true;
  }
  return false;
}

async function copyLink() {
  const url = new URL(location.href);
  url.search = "";
  url.hash = "playground";
  url.searchParams.set("f", ui.filter.value);
  url.searchParams.set("out", ui.outbound.checked ? "1" : "0");
  if (ui.iface.value) url.searchParams.set("iface", ui.iface.value);
  history.replaceState(null, "", url);
  try {
    await navigator.clipboard.writeText(url.href);
    ui.share.textContent = "Copied";
  } catch {
    ui.share.textContent = "Link in the address bar";
  }
  setTimeout(() => (ui.share.textContent = "Copy link"), 2000);
}

async function main() {
  ui.examples.replaceChildren(
    new Option("Choose an example…", ""),
    ...EXAMPLES.map((ex, i) => new Option(ex.name, String(i))),
  );
  if (!initialFilter()) {
    ui.filter.value = EXAMPLES[0].filter;
  }

  try {
    const module = await import("./pkg/avulse_wasm.js");
    await module.default();
    engine = module;
  } catch (err) {
    ui.status.className = "pg-status error";
    ui.status.textContent =
      "The filter engine could not be loaded in this browser (it needs WebAssembly). " +
      "You can still try filters with the avulse CLI.";
    console.error(err);
    return;
  }

  samples = engine.samples();
  renderSamples();
  const allFields = engine.fields();
  renderFields(allFields);

  const run = debounce(analyze, 120);
  ui.filter.addEventListener("input", run);
  ui.iface.addEventListener("input", run);
  ui.outbound.addEventListener("change", analyze);
  ui.examples.addEventListener("change", () => {
    if (ui.examples.value !== "") loadExample(Number(ui.examples.value));
  });
  ui.share.addEventListener("click", copyLink);
  ui.fieldSearch.addEventListener("input", () => renderFields(allFields));
  ui.hex.addEventListener("input", debounce(runCustom, 120));
  ui.link.addEventListener("change", runCustom);
  ui.diagnostics.addEventListener("click", () => {
    const d = lastDiagnostics[0];
    if (d) {
      ui.filter.focus();
      ui.filter.setSelectionRange(d.start, Math.max(d.end, d.start + 1));
    }
  });
  ui.diagnostics.title = "Click to select the span in the filter";
  analyze();
}

main();
