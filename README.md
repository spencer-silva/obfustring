# Obfustring

**`strings`, but it notices obfuscation and tries to undo it.** Drop a suspicious file into the page and you get an obfuscation score, an entropy map, PE header analysis, extracted IOCs, and strings recovered from base64, hex, XOR, ROT13 and reversed encodings, each shown with the decode chain that produced it.

Everything runs in your browser. The page's Content-Security-Policy sets `connect-src 'none'`, so it **cannot** make network requests. The sample never leaves your machine, which makes it usable for samples you aren't allowed to upload to VirusTotal.

## Why

`strings` only finds text that sits in the file in plaintext. Malware authors know this, so C2 URLs, commands and API names get encoded. A near-empty `strings` output is itself a signal, though, and many encodings are cheap to reverse. Obfustring does both: it scores *how* obfuscated a file looks, then tries to peel the easy layers.

## What v1 does

| Area | Details |
|---|---|
| PE parsing | Headers, sections (with per-section entropy and R/W/X flags), imports (32/64-bit), entry-point section, overlay, .NET detection |
| Obfuscation heuristics | Packer section names and signatures (UPX, ASPack, MPRESS, Themida, VMProtect, Enigma, PECompact, …), high-entropy code, empty-on-disk executable sections, W+X sections, odd entry point, tiny or missing import table, low string density, API names hidden as strings, embedded / XOR-encoded executables |
| Strings | ASCII + UTF-16LE with offsets, regex filter |
| IOCs | URLs, IPv4 (private and version-like filtered out), domains, emails, registry keys, Windows paths, crypto wallets, user agents, LOLBin command lines. All defanged, with a benign-domain allowlist (cert authorities, manifests) |
| Decoders | Recursive base64 / hex / `\x` escapes (up to 3 layers, UTF-16 aware), known-plaintext single-byte XOR brute force, ROT13, reversed strings. Results are ranked by an IOC- and language-based score to keep noise out |
| Payloads | Embedded PE files, XOR-encoded PE (DOS-stub known plaintext), base64-encoded PE/zip/gzip/ELF/PDF |
| Output | Defanged IOC copy, full JSON export, SHA-1/SHA-256 with click-through VirusTotal / MalwareBazaar lookups (sends the hash only, and only when you click) |

Tested: zero decoded false positives across 100 MB of random data and eight benign Windows binaries; a 20 MB file analyzes in about 1.5 s.

## Limits (be honest about these)

This is **static** analysis. It will not see through:

- custom packers / protectors (it *flags* them, but doesn't unpack them)
- strings decrypted at runtime with RC4/AES/custom routines
- stack strings built instruction by instruction
- API hashing
- .NET string encryption (ConfuserEx etc.)

For those, use [FLOSS](https://github.com/mandiant/flare-floss), a debugger, or a sandbox. The roadmap below closes some of the gap.

## Run it

**GitHub Pages:** push this folder to a repo → Settings → Pages → deploy from branch `main`, folder `/` (root). The `.nojekyll` file is already there.

**Locally:** the analysis runs in a Web Worker, which browsers won't load from `file://`, so serve the folder:

```bash
python3 -m http.server 8000   # then open http://localhost:8000
```

**CLI / tests (Node 18+):**

```bash
python3 tests/make_sample.py sample.bin host.exe embed.exe   # harmless binary with planted encoded IOCs
node tests/run.js sample.bin
```

## Safety design

- The sample is read as bytes and never executed or emulated.
- Every value taken from the sample is rendered with `textContent`. There's no `innerHTML` anywhere, and the CSP forbids inline scripts and styles, so strings like `<script>` in a sample stay inert. The e2e test covers this.
- Parsing runs in a Web Worker with a 90-second watchdog and a 64 MB cap, so a crafted file can't freeze the tab.
- Still: handle live malware in an analysis VM.

## Files

```
index.html    page + CSP
style.css
app.js        UI (rendering, chart, export)
analyzer.js   all analysis — no DOM, runs in a Worker or Node
tests/        sample generator + CLI runner
```

## Roadmap

- **v2:** UPX unpacking, multi-byte / rolling XOR (known-plaintext key recovery), zlib/gzip inflation of decoded blobs, .NET `#US` heap parsing, YARA-style custom rules
- **v3:** stack-string recovery via Capstone (WASM)
- **v4:** lightweight emulation of decoding routines (Unicorn WASM)

## License

MIT
