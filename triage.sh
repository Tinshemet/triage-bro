#!/usr/bin/env bash
# triage-bro — a quick, static-first malware triage tool for downloaded archives & files.
# For folks who get handed sketchy installers by less-technical friends/siblings.
#
# It NEVER executes samples except in the sandboxed Tier 3 VM. Tiers 1-2 are static only:
# list, hash, strings, ClamAV, YARA, capa — nothing is run.
#
# Usage:
#   triage-bro [--tier=N] [--setup] [--no-update] <path> [more paths...]
#     --tier=1   (default) fast static: hash · encrypted-check · IOC strings · ClamAV · VirusTotal-by-hash
#     --tier=2   deep static: everything in 1 + entropy/packer · Authenticode signature · YARA · capa
#     --tier=3   dynamic: detonate in an isolated Windows VM, report behaviour via guest agent  [STUB]
#     --setup    force a tool/DB provisioning pass and exit
#     --no-update  skip the (throttled) DB/rule refresh this run
#   <path> may be a DIRECTORY (archives inside), an ARCHIVE (.zip/.rar/.7z), or ANY FILE (a sample).
#   Set VT_API_KEY in the environment to enable the VirusTotal hash lookup.
set -uo pipefail

# ---- config / state ----------------------------------------------------------
STATE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/triage-bro"
RULES_DIR="$STATE_DIR/signature-base"          # Neo23x0 curated YARA rules
STAMP="$STATE_DIR/.last_update"
UPDATE_EVERY=$((24*3600))
mkdir -p "$STATE_DIR"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"; [ -n "$SELF_DIR" ] || SELF_DIR="$(dirname "$0")"

EXE_RE='\.(exe|dll|scr|bat|cmd|com|vbs|vbe|js|jse|ps1|msi|jar|hta|cpl|sys)$'
IOC='https?://[A-Za-z0-9._~:/?#@!$&+%-]{6,}|(\b[0-9]{1,3}\.){3}[0-9]{1,3}\b|powershell|Invoke-Expression|Invoke-WebRequest|FromBase64String|DownloadString|DownloadFile|bitsadmin|certutil|mshta|wscript|cscript|schtasks|reg add|CurrentVersion\\Run|Add-MpPreference|Set-MpPreference|DisableRealtimeMonitoring|vssadmin|bcdedit|netsh advfirewall|nsExec|rundll32|regsvr32'
REDFLAG='disable.{0,15}(antivirus|defender|av)|turn off.{0,15}(antivirus|defender)|add.{0,15}exclusion|exclude.{0,15}(folder|defender)|block.{0,15}firewall|run as admin|disconnect.{0,15}internet|do not update|ignore.{0,10}(warning|detection)'

TIER=1; DO_SETUP=0; NO_UPDATE=0; PATHS=()
for a in "$@"; do case "$a" in
  --tier=*) TIER="${a#*=}";;
  --setup)  DO_SETUP=1;;
  --no-update) NO_UPDATE=1;;
  -h|--help) sed -n '2,16p' "$0"; exit 0;;
  *) PATHS+=("$a");;
esac; done

log(){ printf '%s\n' "$*" >&2; }

# ---- provisioning: fetch tools & DBs so the user never hand-updates ----------
provision(){
  log "[setup] checking tools for tier $TIER…"
  local need=()
  # tier 1 essentials -> package:binary
  local base=( "p7zip-full:7z" "unrar:unrar" "clamav:clamscan" "coreutils:sha256sum" "file:file" )
  local deep=( "yara:yara" "osslsigncode:osslsigncode" "python3:python3" )
  local want=( "${base[@]}" ); [ "$TIER" -ge 2 ] && want+=( "${deep[@]}" )
  [ "$TIER" -ge 3 ] && want+=( "radare2:r2" "innoextract:innoextract" )   # tier 3 decompile + installer unpack
  for pt in "${want[@]}"; do command -v "${pt##*:}" >/dev/null || need+=("${pt%%:*}"); done
  if [ ${#need[@]} -gt 0 ] && command -v apt-get >/dev/null; then
    log "[setup] apt install: ${need[*]} (may prompt for sudo once)"
    sudo apt-get install -y "${need[@]}" >/dev/null 2>&1 || log "[setup] WARN: could not install: ${need[*]} — continuing degraded"
  fi
  if [ "$TIER" -ge 2 ]; then   # python tools (venv-safe: try plain pip, then --user)
    python3 -c 'import yara'   2>/dev/null || pip install -q yara-python >/dev/null 2>&1 || pip install --user -q yara-python >/dev/null 2>&1 || true
    python3 -c 'import pefile' 2>/dev/null || pip install -q pefile      >/dev/null 2>&1 || pip install --user -q pefile      >/dev/null 2>&1 || true
    command -v capa >/dev/null || { log "[setup] pip install flare-capa"; pip install -q flare-capa >/dev/null 2>&1 || pip install --user -q flare-capa >/dev/null 2>&1 || true; }
  fi
  # throttled DB / rule refresh
  local now last=0; now=$(date +%s); [ -f "$STAMP" ] && last=$(cat "$STAMP" 2>/dev/null || echo 0)
  if [ "$NO_UPDATE" = 0 ] && { [ "$DO_SETUP" = 1 ] || [ $((now-last)) -gt $UPDATE_EVERY ]; }; then
    log "[setup] refreshing signatures/rules…"
    command -v freshclam >/dev/null && { sudo freshclam >/dev/null 2>&1 || freshclam >/dev/null 2>&1 || true; }
    if [ "$TIER" -ge 2 ]; then
      if [ -d "$RULES_DIR/.git" ]; then git -C "$RULES_DIR" pull -q >/dev/null 2>&1 || true
      else git clone --depth 1 -q https://github.com/Neo23x0/signature-base "$RULES_DIR" >/dev/null 2>&1 || true; fi
    fi
    echo "$now" > "$STAMP"
  fi
}

# capability banner — honest about what's actually available this run
have(){ command -v "$1" >/dev/null; }
banner(){
  log "[triage-bro] tier=$TIER  |  clamav:$(have clamscan&&echo y||echo -) yara:$(have yara&&echo y||echo -) capa:$(have capa&&echo y||echo -) osslsigncode:$(have osslsigncode&&echo y||echo -) VT:${VT_API_KEY:+y}"
  [ -n "${VT_API_KEY:-}" ] || log "[triage-bro] (set VT_API_KEY to enable VirusTotal hash lookups)"
}

provision
[ "$DO_SETUP" = 1 ] && { log "[setup] done."; exit 0; }
banner
[ ${#PATHS[@]} -ge 1 ] || { log "usage: triage-bro [--tier=N] <archive|file|dir> [...]"; exit 2; }

OUT="$(pwd)/triage-report-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$OUT/text" "$OUT/tmp"
HASHES="$OUT/hashes.txt"; REPORT="$OUT/report.md"; : > "$HASHES"
declare -A VERDICT

# ---- helpers -----------------------------------------------------------------
is_archive(){ [[ "${1,,}" =~ \.(zip|rar|7z)$ ]] && return 0
  file -b "$1" 2>/dev/null | grep -qiE 'Zip archive|RAR archive|7-zip archive'; }
lister(){ case "${1,,}" in *.rar) unrar l -p- "$1" 2>/dev/null;; *) 7z l "$1" 2>/dev/null;; esac; }
is_encrypted(){ case "${1,,}" in
    *.rar) unrar l "$1" 2>/dev/null | grep -qE '^\*' ;;
    *)     7z l -slt "$1" 2>/dev/null | grep -qiE 'Encrypted = \+' ;; esac; }
stream(){ case "${1,,}" in *.rar) unrar p -inul "$1" "$2" 2>/dev/null;; *) 7z x -so "$1" "$2" 2>/dev/null;; esac; }
inner_exes(){ case "${1,,}" in
    *.rar) unrar lb "$1" 2>/dev/null | grep -iE "$EXE_RE";;
    *)     7z l -ba -slt "$1" 2>/dev/null | awk -F' = ' '/^Path = /{print $2}' | grep -iE "$EXE_RE";; esac; }
hashrec(){ sha256sum "$1" | awk -v n="$2" '{print $1"  "n}' | tee -a "$HASHES" | awk '{print $1}'; }

# VirusTotal hash lookup (free tier: 4/min -> sleep between calls)
vt_lookup(){ [ -n "${VT_API_KEY:-}" ] || return 0
  python3 - "$1" <<'PY' 2>/dev/null
import os,sys,json,urllib.request
h=sys.argv[1]
req=urllib.request.Request("https://www.virustotal.com/api/v3/files/"+h,
    headers={"x-apikey":os.environ["VT_API_KEY"]})
try:
    d=json.load(urllib.request.urlopen(req,timeout=20))
    s=d["data"]["attributes"]["last_analysis_stats"]
    print("VT: %d/%d malicious  (susp %d)"%(s.get("malicious",0),
          sum(s.values()),s.get("suspicious",0)))
except urllib.error.HTTPError as e:
    print("VT: not found" if e.code==404 else "VT: http %d"%e.code)
except Exception as ex: print("VT: err %s"%ex)
PY
  sleep 16; }

# Tier-2 static file inspection: entropy/packer, Authenticode, YARA, capa
deep_file(){ local tmp="$1" name="$2" out=""
  if python3 -c 'import pefile' 2>/dev/null; then
    out+=$(python3 - "$tmp" <<'PY' 2>/dev/null
import sys,math,pefile
def ent(b):
    if not b: return 0
    from collections import Counter; c=Counter(b); n=len(b)
    return -sum(v/n*math.log2(v/n) for v in c.values())
try:
    pe=pefile.PE(sys.argv[1],fast_load=True)
    hi=[s.Name.decode(errors='replace').strip('\x00') for s in pe.sections if ent(s.get_data())>7.2]
    signed = hasattr(pe,'OPTIONAL_HEADER') and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress!=0
    print(("packed-sections["+",".join(hi)+"] " if hi else "")+("has-embedded-signature" if signed else "UNSIGNED"))
except Exception as e: print("not-a-PE")
PY
)
  fi
  if have osslsigncode; then
    local v; v=$(osslsigncode verify "$tmp" 2>/dev/null | grep -iE 'Signature verification|Signers|Subject' | head -3 | paste -sd' | ')
    [ -n "$v" ] && out+=" | sig: $v"
  fi
  if [ -f "$SELF_DIR/yara_scan.py" ] && python3 -c 'import yara' 2>/dev/null && [ -d "$RULES_DIR/yara" ]; then
    local y; y=$(python3 "$SELF_DIR/yara_scan.py" "$tmp" 2>/dev/null)
    [ -n "$y" ] && out+=" | YARA: $y"
  fi
  if have capa; then
    local c; c=$(timeout 300 capa -q "$tmp" 2>/dev/null | grep -iE 'ATT&CK|persistence|inject|keylog|http|download|anti-|encrypt' | head -8 | sed 's/  */ /g' | paste -sd'; ')
    [ -n "$c" ] && out+=" | capa: $c"
  fi
  printf '%s' "$out"
}

# Tier-3 static decompile / reverse-engineering pass on a PE (no execution)
SUSP_API='(VirtualAllocEx?|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|QueueUserAPC|SetWindowsHookEx|WinExec|ShellExecute[AW]?|CreateProcess[AW]?|URLDownloadToFile[AW]?|InternetOpen[AW]?|WinHttp[A-Za-z]+|Ws2_32|RegSetValue[A-Za-z]*|RegCreateKey[A-Za-z]*|CreateService[AW]?|CryptEncrypt|CryptGenKey|IsDebuggerPresent|CheckRemoteDebugger|GetTickCount|VirtualProtect|LoadLibrary[AW]?|GetProcAddress|AdjustTokenPrivileges)'
decompile_file(){ local tmp="$1" name="$2"
  { echo "### 🔬 decompile — \`$name\`"; echo '```'
    echo "file:   $(file -b "$tmp" 2>/dev/null)"
    objdump -f "$tmp" 2>/dev/null | grep -iE 'file format|architecture|start address' | sed 's/^/hdr:    /'
    echo "-- sections --"
    objdump -h "$tmp" 2>/dev/null | awk 'NR>4 && $2 ~ /^\./{printf "  %-12s size=%-10s vma=%s\n",$2,$3,$4}' | head -14
    echo "-- imported DLLs --"
    objdump -x "$tmp" 2>/dev/null | grep -iE 'DLL Name:' | sed 's/^[[:space:]]*/  /' | head -20
    echo "-- suspicious imported APIs (capability hints) --"
    { objdump -x "$tmp" 2>/dev/null; strings -n 6 "$tmp" 2>/dev/null; } | grep -oiE "$SUSP_API" | sort -u | head -24 | sed 's/^/  /'
    if have r2; then echo "-- entrypoint (radare2) --"; timeout 90 r2 -e bin.relocs.apply=true -qc 'aa;pdf@entry0' "$tmp" 2>/dev/null | head -45
    else echo "-- disasm @ .text (objdump, bounded) --"; timeout 90 objdump -d "$tmp" 2>/dev/null | sed -n '/<\.text/,/ret/p' | head -40; fi
    # installer? a large appended overlay = a self-extractor/installer whose PAYLOAD is the real target
    python3 - "$tmp" <<'PY' 2>/dev/null
import sys,pefile
try:
  pe=pefile.PE(sys.argv[1],fast_load=True); end=max((s.PointerToRawData+s.SizeOfRawData) for s in pe.sections)
  import os; ov=os.path.getsize(sys.argv[1])-end
  if ov>1_000_000: print("-- overlay: %.1f MB appended after PE (installer/SFX payload — unpack to clear it)"%(ov/1e6))
except Exception: pass
PY
    if have innoextract && innoextract -l "$tmp" >/dev/null 2>&1; then
      echo "-- installer payload (innoextract) --"; innoextract -l "$tmp" 2>/dev/null | grep -iE '\.(exe|dll|bat|cmd|vbs|ps1|scr)|keygen|patch|crack|activat' | head -25
    elif 7z l "$tmp" >/dev/null 2>&1; then
      echo "-- installer payload (7z) --"; 7z l "$tmp" 2>/dev/null | grep -iE '\.(exe|dll|bat|cmd|vbs|ps1|scr)|keygen|patch|crack|activat' | head -25
    fi
    if have capa; then echo "-- capa capabilities --"; timeout 300 capa -q "$tmp" 2>/dev/null | grep -iE 'ATT&CK|CAPABILITY|persist|inject|discover|command|exfil|http|download|anti-|encrypt|keylog' | sed 's/  */ /g' | head -24; fi
    echo '```'; } >> "$REPORT"
}

echo "# triage-bro report  (tier $TIER)" > "$REPORT"
echo "_$(date)_  · ClamAV $([ "$(have clamscan;echo $?)" = 0 ] && clamscan --version | cut -d/ -f1 | cut -d' ' -f2)" >> "$REPORT"; echo >> "$REPORT"

# ---- classify inputs ---------------------------------------------------------
ARCHIVES=(); SAMPLES=()
for p in "${PATHS[@]}"; do
  if [ -d "$p" ]; then
    while IFS= read -r -d '' f; do ARCHIVES+=("$f"); done \
      < <(find "$p" -maxdepth 1 -type f \( -iname '*.zip' -o -iname '*.rar' -o -iname '*.7z' \) -print0)
  elif [ -f "$p" ]; then is_archive "$p" && ARCHIVES+=("$p") || SAMPLES+=("$p")
  else log "skip (not found): $p"; fi
done
[ $(( ${#ARCHIVES[@]} + ${#SAMPLES[@]} )) -gt 0 ] || { log "no archives or files to scan"; exit 1; }

# ---- archives ----------------------------------------------------------------
for f in "${ARCHIVES[@]}"; do
  b="$(basename "$f")"; log "=== [archive] $b ==="
  ah=$(hashrec "$f" "$b"); vt=$(vt_lookup "$ah")
  lister "$f" > "$OUT/text/list__$b.txt"
  enc=no; is_encrypted "$f" && enc=yes
  td="$OUT/text/$b.d"; mkdir -p "$td"; rf=""
  case "${f,,}" in
    *.rar) unrar e -p- -o+ -idq "$f" '*.nfo' '*.url' '*.txt' "$td/" 2>/dev/null;;
    *)     7z e -p- -y -bso0 -bsp0 -o"$td" "$f" '*.nfo' '*.url' '*.txt' >/dev/null 2>&1;;
  esac
  compgen -G "$td/*" >/dev/null && rf="$(cat "$td"/* 2>/dev/null | iconv -f CP437 -t UTF-8 2>/dev/null | grep -Eio "$REDFLAG" | sort -u | paste -sd'; ')"
  ioc=""; deep=""
  if [ "$enc" = no ]; then
    while IFS= read -r ex; do [ -n "$ex" ] || continue
      hit="$(stream "$f" "$ex" | tee >(sha256sum | awk -v n="$b::$ex" '{print $1"  "n}' >> "$HASHES") \
             | strings -n 8 | grep -Eioh "$IOC" | sort -u | head -8 | paste -sd',' )"
      [ -n "$hit" ] && ioc="$ioc [$ex → $hit]"
      if [ "$TIER" -ge 2 ]; then       # extract one exe at a time for deep inspection, then delete
        t="$OUT/tmp/sample.bin"; stream "$f" "$ex" > "$t" 2>/dev/null
        d="$(deep_file "$t" "$ex")"; [ -n "$d" ] && deep="$deep"$'\n'"  - \`$ex\`: $d"; rm -f "$t"
      fi
    done < <(inner_exes "$f")
  fi
  V="LOW-CONFIDENCE"; [ "$enc" = yes ] && V="UNSCANNED(encrypted)"
  case "$deep" in *YARA:*) [ "$V" = "LOW-CONFIDENCE" ] && V="SUSPICIOUS(yara)";; esac
  VERDICT["$b"]="$V"
  { echo "## $b";
    echo "- encrypted: **$enc**";
    [ -n "$vt" ]   && echo "- $vt";
    [ -n "$rf" ]   && echo "- ⚠ install-text red flags: $rf";
    [ -n "$ioc" ]  && echo "- ⚠ inner-exe indicators:$ioc";
    [ -n "$deep" ] && echo "- deep static:$deep";
    echo; } >> "$REPORT"
done

# ---- loose files -------------------------------------------------------------
for f in "${SAMPLES[@]}"; do
  b="$(basename "$f")"; log "=== [file] $b ==="
  fh=$(hashrec "$f" "$b"); vt=$(vt_lookup "$fh")
  ft="$(file -b "$f" 2>/dev/null)"
  ioc="$(strings -n 8 "$f" 2>/dev/null | grep -Eioh "$IOC" | sort -u | head -12 | paste -sd',')"
  deep=""; [ "$TIER" -ge 2 ] && deep="$(deep_file "$f" "$b")"
  VERDICT["$b"]="LOW-CONFIDENCE"; case "$deep" in *YARA:*) VERDICT["$b"]="SUSPICIOUS(yara)";; esac
  { echo "## $b  _(loose file)_";
    echo "- type: $ft";
    [ -n "$vt" ]   && echo "- $vt";
    [ -n "$ioc" ]  && echo "- ⚠ indicators: $ioc";
    [ -n "$deep" ] && echo "- deep static: $deep";
    echo; } >> "$REPORT"
done

# ---- Tier 3: static decompile + (stubbed) dynamic detonation ------------------
if [ "$TIER" -ge 3 ]; then
  log "[tier3] decompiling PEs (static RE, no execution)…"
  echo "## Tier 3 — decompile / reverse-engineering" >> "$REPORT"
  for f in "${ARCHIVES[@]}"; do
    if is_encrypted "$f"; then echo "- \`$(basename "$f")\`: encrypted — cannot extract to decompile" >> "$REPORT"; continue; fi
    while IFS= read -r ex; do [ -n "$ex" ] || continue
      t="$OUT/tmp/dis.bin"; stream "$f" "$ex" > "$t" 2>/dev/null
      log "  decompiling $(basename "$f")::$ex"
      decompile_file "$t" "$(basename "$f")::$ex"; rm -f "$t"
    done < <(inner_exes "$f")
  done
  for f in "${SAMPLES[@]}"; do
    case "$(file -b "$f" 2>/dev/null)" in *PE32*|*MS-DOS*|*executable*) log "  decompiling $(basename "$f")"; decompile_file "$f" "$(basename "$f")";; esac
  done
  { echo; echo "### ⏸ dynamic detonation — STUB";
    echo "Would boot an isolated, snapshotted Windows VM, transfer the sample via the guest agent,";
    echo "run it under Procmon/Autoruns/Wireshark, and return dropped-file/registry/C2 behaviour.";
    echo "Not yet wired — see the Gorgon container-mode design (GORGON-PORT.md)."; echo; } >> "$REPORT"
fi

# ---- ClamAV signature pass ---------------------------------------------------
if have clamscan; then
  log "Running ClamAV (decompresses archives; may take a few minutes)…"
  CL="$OUT/clamscan.log"
  clamscan -r --archive-verbose --max-filesize=2000M --max-scansize=8000M \
    --max-files=50000 --max-recursion=20 --alert-encrypted=yes --detect-pua=yes \
    --heuristic-alerts=yes --tempdir="$OUT/tmp" "${PATHS[@]}" > "$CL" 2>&1
  echo "## ClamAV signature results" >> "$REPORT"
  grep -E 'FOUND' "$CL" | sed 's/^/- 🔴 /' >> "$REPORT" || echo "- (no signature detections)" >> "$REPORT"
  # precedence: a real malware hit outranks PUA/riskware, which outranks the
  # "encrypted archive" heuristic (that's unscannable, NOT a detection).
  while IFS= read -r line; do
    for b in "${!VERDICT[@]}"; do case "$line" in *"$b"*)
      if   [[ "$line" == *Heuristics.Encrypted* ]]; then [ "${VERDICT[$b]}" != INFECTED ] && VERDICT["$b"]="UNSCANNED(encrypted)"
      elif [[ "$line" == *PUA.* ]];                 then [ "${VERDICT[$b]}" != INFECTED ] && VERDICT["$b"]="RISKWARE(PUA)"
      else VERDICT["$b"]="INFECTED"; fi ;; esac; done
  done < <(grep -E 'FOUND' "$CL")
  echo >> "$REPORT"; sed -n '/SCAN SUMMARY/,$p' "$CL" | sed 's/^/    /' >> "$REPORT"
fi

# ---- verdict table -----------------------------------------------------------
{ echo; echo "## Verdicts"; echo; echo "| item | verdict |"; echo "|---|---|";
  for b in "${!VERDICT[@]}"; do echo "| $b | ${VERDICT[$b]} |"; done | sort; } >> "$REPORT"

log ""; log "REPORT:  $REPORT"; log "HASHES:  $HASHES  (paste into VirusTotal)"; log ""
log "===== VERDICTS ====="
for b in "${!VERDICT[@]}"; do printf '  %-55s %s\n' "$b" "${VERDICT[$b]}" >&2; done | sort
ec=0; for b in "${!VERDICT[@]}"; do case "${VERDICT[$b]}" in INFECTED) ec=3;; RISKWARE*|UNSCANNED*|SUSPICIOUS*) [ $ec -lt 2 ] && ec=2;; esac; done
exit $ec
