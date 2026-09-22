#!/usr/bin/env python3
"""triage-bro tier-2 YARA backend via yara-python (no yara CLI / no sudo needed).
Compiles the Neo23x0 signature-base rules once into a cached .yc, then scans a file.
Usage: yara_scan.py <file>   -> prints comma-separated matched rule names (empty if none)."""
import os, sys, glob, yara
STATE = os.path.expanduser("~/.local/share/triage-bro")
RULES = STATE + "/signature-base/yara"
YC    = STATE + "/rules.yc"
EXT   = {"filename": "", "filepath": "", "extension": "", "filetype": "", "md5": "", "owner": ""}

def build():
    good = {}
    for f in glob.glob(RULES + "/*.yar"):
        try:
            yara.compile(filepath=f, externals=EXT)      # keep only files that compile clean
            good[os.path.basename(f)] = f
        except Exception:
            pass
    r = yara.compile(filepaths=good, externals=EXT)
    try: r.save(YC)
    except Exception: pass
    return r

def get_rules():
    rule_files = glob.glob(RULES + "/*.yar")
    if os.path.exists(YC) and rule_files and os.path.getmtime(YC) >= max(os.path.getmtime(p) for p in rule_files):
        try: return yara.load(YC)
        except Exception: pass
    return build()

if __name__ == "__main__":
    if len(sys.argv) < 2 or not os.path.isdir(RULES):
        sys.exit(0)
    try:
        r = get_rules()
        p = sys.argv[1]
        e = os.path.splitext(p)[1].lstrip(".")
        m = r.match(p, externals={**EXT, "filename": os.path.basename(p), "filepath": p, "extension": e}, timeout=30)
        print(",".join(sorted({x.rule for x in m})[:12]))
    except Exception:
        sys.exit(0)
