#!/usr/bin/env python3
"""Run the official 10-sample answer key across six mock modes (60 runs).

Usage:
  python3 scripts/run_original60.py --port 3250 --samples /path/to/malicious-log-samples

The server must already be running with MOCK_GROQ=1 (or MOCK_GEMINI=1).
This script never calls the Groq API.
"""
from __future__ import annotations

import argparse, csv, json, os, sys, time, urllib.request, urllib.error
from pathlib import Path

MODE_FILE_CANDIDATES = ["MOCK_GROQ_MODE_FILE", "MOCK_GEMINI_MODE_FILE"]
DEFAULT_MODE_FILE = "/tmp/fceb-mock-mode"
MODES = ["match", "under", "over", "multi", "benign", "fail429"]
RANK = {
    "UNSCORABLE_GRAY": 0,
    "BASELINE_NEGLIGIBLE_WHITE": 1,
    "BASELINE_MINOR_BLUE": 2,
    "LOW_GREEN": 3,
    "MEDIUM_YELLOW": 4,
    "HIGH_ORANGE": 5,
    "SEVERE_RED": 6,
    "EMERGENCY_BLACK": 7,
}
KEY2CODE = {
    "Critical": "SEVERE_RED",
    "High": "HIGH_ORANGE",
    "Medium": "MEDIUM_YELLOW",
    "Low": "LOW_GREEN",
    "Informational": "BASELINE_NEGLIGIBLE_WHITE",
    "None": "BASELINE_NEGLIGIBLE_WHITE",
}


def post(base, path, body, timeout=600):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        base + path,
        data=data,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def expected(key_path: Path):
    exp = {}
    with key_path.open() as f:
        for row in csv.DictReader(f):
            fn, sev = row["file"], row["severity"] or "None"
            if fn not in exp or RANK[KEY2CODE[sev]] > RANK[KEY2CODE[exp[fn]]]:
                exp[fn] = sev
    return exp


def set_mode(mode: str, mode_file: str):
    Path(mode_file).write_text(mode + "\n")
    os.environ["MOCK_GROQ_MODE_FILE"] = mode_file
    os.environ["MOCK_GEMINI_MODE_FILE"] = mode_file


def run_file(base, samples: Path, fn: str, mode: str, mode_file: str):
    set_mode(mode, mode_file)
    content = (samples / fn).read_text(encoding="utf-8", errors="replace").strip()
    raw = f"=== FILE: {fn} ===\n{content}"
    st, txt = post(base, "/api/triage/inspect", {"rawLogs": raw})
    if st != 200:
        return {"file": fn, "mode": mode, "http": st, "error": txt[:200], "verdict": "ERROR"}
    insp = json.loads(txt)
    ctx = {
        "missionCritical": "unknown",
        "piiExposure": "unknown",
        "authorizedActivity": "unknown",
        "ictContractor": "unknown",
        "skippedAll": True,
    }
    t0 = time.time()
    st2, txt2 = post(
        base,
        "/api/triage/analyze",
        {
            "rawLogs": raw,
            "contextAnswers": ctx,
            "detectedContext": insp.get("clearContextFromLogs"),
        },
    )
    dt = time.time() - t0
    floor = (insp.get("inspectionSummary") or "").split("code-computed minimum floor: ")[-1].rstrip(").")
    rec = {
        "file": fn,
        "mode": mode,
        "http": st2,
        "seconds": round(dt, 2),
        "floor": floor,
    }
    if st2 != 200:
        # fail429 on a clean baseline is expected to surface 429
        rec["error"] = txt2[:240]
        rec["verdict"] = "HTTP_429" if st2 == 429 else "ERROR"
        return rec
    res = json.loads(txt2)
    cards = res.get("scorecards") or []
    top = max((c["severity"]["levelCode"] for c in cards), key=lambda c: RANK.get(c, 0), default="(no scorecards)")
    rec["top"] = top
    rec["name"] = (cards[0]["severity"].get("ncissLevelName") if cards else None)
    rec["color"] = (cards[0]["severity"].get("colorName") if cards else None)
    rec["cards"] = len(cards)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="3250")
    ap.add_argument("--samples", default=os.environ.get("MALICIOUS_LOG_SAMPLES", "/workspace/malicious-log-samples"))
    ap.add_argument("--mode-file", default=os.environ.get("MOCK_GROQ_MODE_FILE", DEFAULT_MODE_FILE))
    ap.add_argument("--host", default="http://127.0.0.1")
    args = ap.parse_args()
    samples = Path(args.samples)
    key = samples / "answer_key.csv"
    if not key.exists():
        sys.exit(f"answer_key.csv not found under {samples}")
    exp = expected(key)
    files = sorted(f for f in os.listdir(samples) if f[:2].isdigit())
    if not files:
        sys.exit(f"no numbered log files in {samples}")
    base = f"{args.host}:{args.port}"
    # health
    try:
        with urllib.request.urlopen(base + "/api/health", timeout=10) as r:
            health = json.loads(r.read().decode())
            print("HEALTH", r.status, health)
            if not health.get("ok"):
                sys.exit("health not ok")
    except Exception as e:
        sys.exit(f"server not reachable at {base}: {e}")

    rows = []
    below = 0
    errors = 0
    expected_429 = 0
    for mode in MODES:
        for fn in files:
            rec = run_file(base, samples, fn, mode, args.mode_file)
            e = exp.get(fn, "None")
            rec["expected"] = e
            if rec.get("verdict") == "HTTP_429":
                # Clean/informational samples may fail closed on 429; malicious samples should still floor if fallback works
                if RANK[KEY2CODE.get(e, "BASELINE_NEGLIGIBLE_WHITE")] <= RANK["LOW_GREEN"]:
                    rec["verdict"] = "OK_EXPECTED_429"
                    expected_429 += 1
                else:
                    # For High/Critical samples the server should fall back to floors (HTTP 200)
                    rec["verdict"] = "UNEXPECTED_429"
                    errors += 1
            elif rec.get("verdict") == "ERROR":
                errors += 1
            else:
                top = rec.get("top") or "(no scorecards)"
                if top == "(no scorecards)":
                    topr = 1
                else:
                    topr = RANK.get(top, 1)
                need = RANK[KEY2CODE[e]]
                if topr >= need:
                    rec["verdict"] = "OK" if topr == need else "ABOVE KEY"
                else:
                    rec["verdict"] = "BELOW KEY"
                    below += 1
                # Label check for the three highlighted samples
                if fn.startswith("07") or fn.startswith("08"):
                    if rec.get("name") != "High" or rec.get("color") != "Orange":
                        if rec["verdict"].startswith("OK") or rec["verdict"] == "ABOVE KEY":
                            rec["verdict"] += " (label? %s %s)" % (rec.get("name"), rec.get("color"))
                if fn.startswith("09"):
                    if rec.get("name") == "Severe":
                        rec["verdict"] += " (Severe leak)"
                        errors += 1
                    elif rec.get("name") != "Critical" or rec.get("color") != "Red":
                        rec["verdict"] += " (label? %s %s)" % (rec.get("name"), rec.get("color"))
            rows.append(rec)
            print(
                f"{rec['mode']:8} {rec['file']:42} expected={rec['expected']:14} "
                f"top={rec.get('top', rec.get('http'))} {rec.get('name') or ''} {rec['verdict']}"
            )

    print()
    print(f"RUNS={len(rows)} BELOW_KEY={below} ERRORS={errors} EXPECTED_429={expected_429}")
    passed = below == 0 and errors == 0 and len(rows) == len(files) * len(MODES)
    print("PASS" if passed else "FAIL")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
