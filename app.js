/*
 * DeobStrings UI. Security rule for this file: every value that came from the
 * sample is rendered with textContent (via el()). Never use innerHTML.
 */
'use strict';

const MAX_SIZE = 64 * 1024 * 1024;
const $ = (id) => document.getElementById(id);
let lastResult = null;
let worker = null;

function el(tag, attrs, ...children) {
  const n = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); return n; };
const hex = (n, w = 8) => '0x' + (n >>> 0).toString(16).padStart(w, '0');
const fmtBytes = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB';
const eClass = (e) => e > 7.2 ? 'e-hi' : e >= 6 ? 'e-mid' : 'e-lo';
const trunc = (s, n = 400) => s.length > n ? s.slice(0, n) + ` … (+${s.length - n} chars)` : s;

function status(msg, isError) {
  const s = $('status');
  s.classList.remove('hidden');
  s.classList.toggle('error', !!isError);
  s.textContent = msg;
}

// ------------------------------------------------------------ input

const drop = $('drop');
$('pick').addEventListener('click', (e) => { e.stopPropagation(); $('file').click(); });
drop.addEventListener('click', () => $('file').click());
drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('file').click(); } });
$('file').addEventListener('change', (e) => { if (e.target.files[0]) handleFile(e.target.files[0]); });
['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
drop.addEventListener('drop', (e) => { const f = e.dataTransfer.files[0]; if (f) handleFile(f); });
// Stop a file dropped outside the zone from being opened by the browser.
window.addEventListener('dragover', (e) => e.preventDefault());
window.addEventListener('drop', (e) => e.preventDefault());

$('reset').addEventListener('click', () => {
  $('report').classList.add('hidden'); $('status').classList.add('hidden');
  drop.classList.remove('hidden'); $('file').value = ''; lastResult = null;
});

async function hashes(buf) {
  if (!(window.crypto && crypto.subtle)) return {};
  const toHex = (ab) => [...new Uint8Array(ab)].map((x) => x.toString(16).padStart(2, '0')).join('');
  const [s1, s256] = await Promise.all([crypto.subtle.digest('SHA-1', buf), crypto.subtle.digest('SHA-256', buf)]);
  return { sha1: toHex(s1), sha256: toHex(s256) };
}

async function handleFile(file) {
  if (file.size > MAX_SIZE) { status(`File is ${fmtBytes(file.size)} — the limit is ${fmtBytes(MAX_SIZE)}.`, true); return; }
  if (file.size === 0) { status('File is empty.', true); return; }
  drop.classList.add('hidden');
  status(`Reading ${file.name} (${fmtBytes(file.size)})…`);
  const buf = await file.arrayBuffer();
  const h = await hashes(buf);

  if (worker) worker.terminate();
  try { worker = new Worker('analyzer.js'); }
  catch (err) {
    status('Could not start the analysis worker. If you opened index.html straight from disk, serve the folder instead (e.g. `python3 -m http.server`).', true);
    drop.classList.remove('hidden');
    return;
  }
  const started = performance.now();
  const watchdog = setTimeout(() => { worker.terminate(); status('Analysis took over 90s and was stopped — the file may be crafted to stall parsers.', true); drop.classList.remove('hidden'); }, 90000);
  worker.onmessage = (e) => {
    const m = e.data;
    if (m.type === 'progress') status(`${file.name}: ${m.stage}…`);
    else if (m.type === 'error') { clearTimeout(watchdog); status('Analysis failed: ' + m.message, true); drop.classList.remove('hidden'); }
    else if (m.type === 'result') {
      clearTimeout(watchdog);
      lastResult = { file: { name: file.name, size: file.size, type: file.type, ...h }, ...m.result };
      $('status').classList.add('hidden');
      render(lastResult, performance.now() - started);
    }
  };
  worker.onerror = (e) => { clearTimeout(watchdog); status('Worker error: ' + (e.message || 'unknown'), true); drop.classList.remove('hidden'); };
  worker.postMessage({ buffer: buf }, [buf]);
}

// ------------------------------------------------------------ render

function render(r, ms) {
  $('report').classList.remove('hidden');
  $('r-name').textContent = r.file.name;
  $('r-meta').textContent = `${fmtBytes(r.size)} · analyzed in ${(ms / 1000).toFixed(2)}s · ${r.pe.isPE ? `PE ${r.pe.machine}${r.pe.is64 ? ' (64-bit)' : ''}${r.pe.isDLL ? ' DLL' : ''}${r.pe.isDotNet ? ' .NET' : ''}` : 'not a PE file'}`;

  const sev = r.score >= 50 ? 'high' : r.score >= 20 ? 'medium' : 'low';
  $('verdict-card').className = 'card verdict sev-' + sev;
  $('r-score').textContent = r.score + ' / 100';
  $('r-verdict').textContent = r.verdict;
  $('r-meter').style.width = r.score + '%'; // CSSOM, allowed by CSP

  const hz = clear($('r-hashes'));
  if (r.file.sha256) {
    hz.append(el('div', { class: 'kv' },
      el('span', { text: 'SHA-256' }), el('span', { class: 'hash', text: r.file.sha256 }),
      el('span', { text: 'SHA-1' }), el('span', { class: 'hash', text: r.file.sha1 }),
      el('span', { text: 'Lookup' }), el('span', null,
        // Only the hash leaves the page, and only if you click.
        el('a', { href: 'https://www.virustotal.com/gui/file/' + r.file.sha256, target: '_blank', rel: 'noopener noreferrer', text: 'VirusTotal' }), ' · ',
        el('a', { href: 'https://bazaar.abuse.ch/browse.php?search=sha256%3A' + r.file.sha256, target: '_blank', rel: 'noopener noreferrer', text: 'MalwareBazaar' }))));
  } else hz.append(el('span', { class: 'muted', text: 'Hashing needs a secure context (https or localhost).' }));

  const fz = clear($('r-file'));
  const rows = [['Size', fmtBytes(r.size)], ['Entropy', r.entropy.toFixed(3)], ['Strings', r.strings.length.toLocaleString() + (r.stringsTruncated ? '+ (capped)' : '')]];
  if (r.pe.isPE) {
    rows.push(['Entry point', hex(r.pe.entryPoint) + (r.pe.entrySection ? ` (${r.pe.entrySection})` : '')]);
    rows.push(['Compiled', r.pe.timestamp ? new Date(r.pe.timestamp * 1000).toISOString().slice(0, 19).replace('T', ' ') + ' UTC' : '—']);
  }
  fz.append(el('div', { class: 'kv' }, rows.flatMap(([k, v]) => [el('span', { text: k }), el('span', { text: v })])));

  renderFindings(r);
  drawChart(r);
  renderIocs(r);
  renderDecoded(r);
  renderSections(r);
  renderImports(r);
  renderStrings(r);
}

function renderFindings(r) {
  const box = clear($('findings'));
  $('c-findings').textContent = r.findings.length;
  if (!r.findings.length) box.append(el('p', { class: 'muted', text: 'Nothing suspicious found by the v1 heuristics.' }));
  for (const f of r.findings) {
    box.append(el('div', { class: 'finding' },
      el('span', { class: 'sev ' + f.severity, text: f.severity }),
      el('div', null, el('div', { class: 't', text: f.title + (f.points ? `  (+${f.points})` : '') }), el('div', { class: 'd', text: f.detail }))));
  }
  if (r.pe.errors && r.pe.errors.length && r.pe.errors[0] !== 'No MZ header — not a PE file') {
    box.append(el('div', { class: 'finding' }, el('span', { class: 'sev medium', text: 'parse' }),
      el('div', null, el('div', { class: 't', text: 'Malformed PE structure' }), el('div', { class: 'd', text: r.pe.errors.join('; ') }))));
  }
}

function drawChart(r) {
  const cv = $('chart');
  const dpr = window.devicePixelRatio || 1;
  const W = cv.clientWidth, H = 180;
  cv.width = W * dpr; cv.height = H * dpr;
  const g = cv.getContext('2d');
  g.scale(dpr, dpr);
  g.clearRect(0, 0, W, H);
  const pts = r.chart.points, n = pts.length, pad = 18;
  const y = (e) => H - pad - (e / 8) * (H - pad * 2);
  // guide lines at 6 and 7.2
  g.strokeStyle = '#2a3441'; g.lineWidth = 1; g.font = '10px ui-monospace, monospace'; g.fillStyle = '#8b98a8';
  for (const e of [0, 6, 7.2, 8]) { g.beginPath(); g.moveTo(30, y(e)); g.lineTo(W, y(e)); g.stroke(); g.fillText(String(e), 4, y(e) + 3); }
  const bw = (W - 30) / n;
  pts.forEach((p, i) => {
    g.fillStyle = p.entropy > 7.2 ? '#ff5d5d' : p.entropy >= 6 ? '#ffb547' : '#5fd38d';
    g.fillRect(30 + i * bw, y(p.entropy), Math.max(1, bw - 0.5), H - pad - y(p.entropy));
  });
  // section boundaries
  if (r.pe.isPE) {
    g.strokeStyle = '#4cc2ff88'; g.fillStyle = '#4cc2ff';
    let lastLabel = -Infinity;
    for (const s of r.pe.sections) {
      if (!s.rawSize) continue;
      const x = 30 + (s.rawPtr / r.size) * (W - 30);
      g.beginPath(); g.moveTo(x, 4); g.lineTo(x, H - pad); g.stroke();
      if (x - lastLabel > 52) { g.fillText(s.name.slice(0, 8), x + 2, 12); lastLabel = x; } // hover shows the rest
    }
  }
  const tip = $('chart-tip');
  cv.onmousemove = (e) => {
    const rect = cv.getBoundingClientRect();
    const i = Math.floor((e.clientX - rect.left - 30) / bw);
    if (i < 0 || i >= n) { tip.classList.add('hidden'); return; }
    const p = pts[i];
    const sec = r.pe.isPE ? r.pe.sections.find((s) => p.offset >= s.rawPtr && p.offset < s.rawPtr + s.rawSize) : null;
    tip.textContent = `${hex(p.offset)}  H=${p.entropy.toFixed(2)}${sec ? '  ' + sec.name : r.pe.overlay && p.offset >= r.pe.overlay.offset ? '  overlay' : ''}`;
    tip.classList.remove('hidden');
    tip.style.left = Math.min(e.clientX - rect.left + 10, W - 220) + 'px';
  };
  cv.onmouseleave = () => tip.classList.add('hidden');
}
window.addEventListener('resize', () => { if (lastResult) drawChart(lastResult); });

function visibleIocs(r) { return r.iocs.filter((i) => $('show-benign').checked || !i.benign); }

function renderIocs(r) {
  const box = clear($('iocs'));
  const list = visibleIocs(r);
  const hidden = r.iocs.length - list.length;
  $('c-iocs').textContent = list.length + (hidden ? ` (+${hidden} benign hidden)` : '');
  if (!list.length) { box.append(el('p', { class: 'muted', text: 'No IOCs found.' })); return; }
  box.append(el('table', null,
    el('thead', null, el('tr', null, ['Type', 'Value (defanged)', 'Found', 'Offset'].map((h) => el('th', { text: h })))),
    el('tbody', null, list.map((i) => el('tr', { class: i.benign ? 'benign' : null },
      el('td', null, el('span', { class: 'pill', text: i.type + (i.class && i.class !== 'public' ? ' · ' + i.class : '') })),
      el('td', { class: 'val', text: trunc(i.defanged, 300) }),
      el('td', null, i.source === 'decoded' ? el('span', { class: 'pill dec', text: 'decoded: ' + i.method }) : el('span', { class: 'pill', text: 'plaintext' })),
      el('td', { class: 'mono', text: i.offset != null ? hex(i.offset) : '' }))))));
}
$('show-benign').addEventListener('change', () => lastResult && renderIocs(lastResult));

function renderDecoded(r) {
  const box = clear($('decoded'));
  $('c-decoded').textContent = r.decoded.length;
  if (!r.decoded.length) { box.append(el('p', { class: 'muted', text: 'No hidden strings recovered with base64 / hex / single-byte XOR / ROT13 / reversal.' })); return; }
  box.append(el('table', null,
    el('thead', null, el('tr', null, ['Offset', 'Recovered via', 'Score', 'Value'].map((h) => el('th', { text: h })))),
    el('tbody', null, r.decoded.map((d) => el('tr', null,
      el('td', { class: 'mono', text: hex(d.origin) }),
      el('td', null, el('span', { class: 'pill ' + (d.magic ? 'bad' : 'dec'), text: d.method })),
      el('td', { class: 'mono', text: String(d.score) }),
      el('td', { class: 'val' }, d.magic ? el('strong', { text: d.magic + ': ' }) : null, trunc(d.value)))))));
}

function renderSections(r) {
  $('pe-sec').classList.toggle('hidden', !r.pe.isPE);
  if (!r.pe.isPE) return;
  const box = clear($('sections'));
  box.append(el('table', null,
    el('thead', null, el('tr', null, ['Name', 'Virtual addr', 'Virtual size', 'Raw ptr', 'Raw size', 'Flags', 'Entropy'].map((h) => el('th', { text: h })))),
    el('tbody', null, r.pe.sections.map((s) => el('tr', null,
      el('td', { class: 'mono', text: s.name || '(unnamed)' }),
      el('td', { class: 'mono', text: hex(s.virtualAddress) }),
      el('td', { class: 'mono', text: hex(s.virtualSize) }),
      el('td', { class: 'mono', text: hex(s.rawPtr) }),
      el('td', { class: 'mono', text: hex(s.rawSize) }),
      el('td', { class: 'mono', text: (s.read ? 'R' : '-') + (s.write ? 'W' : '-') + (s.exec ? 'X' : '-') }),
      el('td', { class: 'mono ' + eClass(s.entropy), text: s.entropy.toFixed(3) }))),
    r.pe.overlay ? el('tr', null, el('td', { class: 'mono', text: '[overlay]' }), el('td'), el('td'),
      el('td', { class: 'mono', text: hex(r.pe.overlay.offset) }), el('td', { class: 'mono', text: hex(r.pe.overlay.size) }), el('td'),
      el('td', { class: 'mono ' + eClass(r.pe.overlay.entropy), text: r.pe.overlay.entropy.toFixed(3) })) : null)));
}

function renderImports(r) {
  $('pe-imp').classList.toggle('hidden', !r.pe.isPE);
  if (!r.pe.isPE) return;
  const box = clear($('imports'));
  $('c-imports').textContent = `${r.pe.importCount} functions · ${r.apis.imported.length} flagged`;
  const sus = new Map(r.apis.imported.map((a) => [a.name, a.group]));
  if (r.apis.imported.length) {
    const groups = {};
    for (const a of r.apis.imported) (groups[a.group] = groups[a.group] || []).push(a.name);
    box.append(el('p', { class: 'small' }, el('strong', { text: 'Capabilities suggested by imports: ' }), Object.keys(groups).join(' · ')));
  }
  if (r.apis.stringOnly.length) box.append(el('p', { class: 'small' }, el('strong', { text: 'API names hidden as strings (not imported): ' }), r.apis.stringOnly.join(', ')));
  if (!r.pe.imports.length) box.append(el('p', { class: 'muted', text: 'No import table.' }));
  for (const d of r.pe.imports) {
    box.append(el('div', { class: 'dll', text: `${d.dll} (${d.functions.length})` }),
      el('div', { class: 'funcs' }, d.functions.map((f) => el('span', { class: 'fn' + (sus.has(f) ? ' sus' : ''), title: sus.get(f) || null, text: f }))));
  }
}

function renderStrings(r) {
  const box = clear($('strings'));
  const min = Math.max(4, +$('s-min').value || 4);
  const encSel = $('s-enc').value;
  let re = null;
  const q = $('s-filter').value.trim();
  if (q) { try { re = new RegExp(q, 'i'); } catch { re = { test: (s) => s.toLowerCase().includes(q.toLowerCase()) }; } }
  const LIMIT = 3000;
  let shown = 0, total = 0;
  const frag = document.createDocumentFragment();
  for (const s of r.strings) {
    if (s.value.length < min || (encSel && s.enc !== encSel) || (re && !re.test(s.value))) continue;
    total++;
    if (shown < LIMIT) {
      frag.append(el('div', { class: 'srow' }, el('span', { class: 'off', text: hex(s.offset) }), el('span', { class: 'off', text: s.enc === 'ascii' ? 'A' : 'U16' }), el('span', { class: 'v', text: trunc(s.value, 600) })));
      shown++;
    }
  }
  box.append(frag);
  if (total > shown) box.append(el('div', { class: 'more', text: `Showing ${shown.toLocaleString()} of ${total.toLocaleString()} — narrow the filter or export JSON for the rest.` }));
  $('c-strings').textContent = total.toLocaleString();
}
let sTimer;
for (const id of ['s-filter', 's-enc', 's-min']) $(id).addEventListener('input', () => { clearTimeout(sTimer); sTimer = setTimeout(() => lastResult && renderStrings(lastResult), 200); });

// ------------------------------------------------------------ export

$('export').addEventListener('click', () => {
  if (!lastResult) return;
  const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
  const a = el('a', { href: URL.createObjectURL(blob), download: (lastResult.file.sha256 || 'report').slice(0, 16) + '.deobstrings.json' });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
});

$('copy-iocs').addEventListener('click', async () => {
  if (!lastResult) return;
  const text = visibleIocs(lastResult).map((i) => `${i.type}\t${i.defanged}\t${i.source === 'decoded' ? 'decoded:' + i.method : 'plaintext'}`).join('\n');
  try { await navigator.clipboard.writeText(text || '(no IOCs)'); $('copy-iocs').textContent = 'Copied ✓'; }
  catch { $('copy-iocs').textContent = 'Copy failed'; }
  setTimeout(() => { $('copy-iocs').textContent = 'Copy IOCs (defanged)'; }, 1500);
});
