# triage-bro

> A quick-and-easy, static-first malware triage tool for people who get handed sketchy installers by less-technical friends and siblings.

### ⚠️ This is a DIY ~15-minute craft, not a product.

It was hacked together in a single session after a family member almost got hacked by a
cracked audio-plugin installer — one of the archives turned out to be carrying the **DarkComet RAT**.
It doesn't invent new detection; it wraps proven engines (**ClamAV**, **YARA**, **capa**) into one
repeatable, *safe* workflow so a non-expert can vet a download before running it. It's deliberately
honest about what it is and isn't (see [How good is it?](#how-good-is-it-measured)).

---

## What it does

Static-first — it **never executes a sample** except in the optional, isolated tier-3 VM. Point it at
a directory, an archive (`.zip/.rar/.7z`, including nested and encrypted), or any loose file:

| tier | what runs | catches |
|------|-----------|---------|
| **1** (default) | hash · encrypted-archive check · IOC strings · **ClamAV** · VirusTotal-by-hash | known signatures, droppers, riskware |
| **2** | + entropy/packer · Authenticode signature · **YARA** · **capa** capabilities · PE **decompile** | families & APTs ClamAV misses, packed/unsigned installers |
| **3** | + **detonation** in an isolated Windows VM (behavioural) | script/mobile/behavioural malware static can't see |

Verdicts: `CLEAN` · `LOW-CONFIDENCE` · `SUSPICIOUS(yara)` · `RISKWARE(PUA)` · `UNSCANNED(encrypted)` · `INFECTED`.
It also prints a `hashes.txt` ready to paste into VirusTotal, and (tier 3) unpacks installer payloads.

## Install

```bash
# system engines (see SYSTEM-DEPS.md)
sudo apt-get install -y p7zip-full unrar clamav && sudo freshclam
# python deps
pip install -r requirements.txt
# make the alias
ln -s "$PWD/triage.sh" ~/.local/bin/triage-bro   # or add an alias
```

It also **self-provisions** missing tools + fresh signature DBs on first run (`triage-bro --setup`).

## Usage

```bash
triage-bro ~/Downloads/some-folder      # tier 1, scans archives inside
triage-bro --tier=2 suspicious.zip      # deep static (YARA/capa/decompile)
triage-bro --tier=3 installer.exe       # + VM detonation (heavy)
export VT_API_KEY=...                    # enable VirusTotal hash lookups
```

## How good is it? (measured)

Benchmarked against **50 real malware families** (theZoo) + **50 benign files**:

| engine | family detection | false-positives |
|--------|------------------|-----------------|
| tier 1 — ClamAV | **71%** (36/51) | **0%** (0/50) |
| tier 1+2 — +YARA/capa | **75%** (38/51) | **0%** (0/50) |

- **0% false-positives** is the point — it doesn't cry wolf.
- YARA specifically recovered the **EquationGroup APT** sample ClamAV missed.
- The ~25% it misses are mostly **scripts / mobile / behavioural** malware — that's what tier 3 is for.

**Honest take:** it's an *orchestrator* around existing engines, not novel detection. Great as a
personal "should I run this download?" vetting tool; **not** a replacement for VirusTotal, CAPE, or a
commercial sandbox. Solid-hobbyist with a real benchmark — which is more than most weekend tools ship.

## Safety / disclaimer

- **Static-first**; only tier 3 runs a sample, and only in a network-isolated VM.
- Single-engine results are weak evidence of safety — **a clean scan is not a clean bill of health**,
  especially for encrypted or packed files. Escalate: VirusTotal → tier 2 → detonation.
- For **authorized, defensive use** (vetting your own downloads / analysing samples you're allowed to).

---

## Roadmap → the Gorgon port

triage-bro is the **DIY prototype** of a capability that graduates into
**[Gorgon](#)** (my purple-team platform) as the **defensive anti-tool of the "0-day forge"** — the
forge *authors* a simulated exploit and proves it on Gorgon's VM-fleet oracle; this *ingests* a
hostile artifact and proves what it does on the same fleet. Same substrate, opposite polarity.

How the weekend bash craft here becomes a hardened, integrated ability there:

- **Tiers 1–2 (static)** → a **Barenboim (blue-team) ability** `{ sample → verdict + findings }`,
  writing into Gorgon's existing findings/method stores instead of a text report. Deterministic where
  possible (Gorgon's "derive-first" ethos), model only for triage/summary.
- **Tier 3 (detonation)** → rides Gorgon's **Container mode** (an isolated analysis VM), gated by the
  **container network-isolation scan** that *proves* the quarantine holds, reporting behaviour over the
  serial-agent seam (no in-guest agent to trust).
- **The twist:** Gorgon's anti-VM / stealth work — normally offensive — flips into a **blue-team asset**
  here, because malware that detects a VM won't detonate.

In short: **the bash you see in this repo is the sketch; the Gorgon port is the engineered version.**

## License

[Apache-2.0](LICENSE)
