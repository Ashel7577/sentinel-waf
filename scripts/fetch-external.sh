#!/usr/bin/env bash
# Downloads third-party payload lists (SecLists) into eval/external so the WAF
# is also measured on attacks its author did not write.
set -euo pipefail
cd "$(dirname "$0")/.."
base="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
out="eval/external/attack"
mkdir -p "$out"

fetch() { # <category> <path>...
  local cat="$1"; shift
  : > "$out/$cat.txt"
  for p in "$@"; do
    curl -fsSL --retry 3 -m 120 "$base/$p" >> "$out/$cat.txt"
    echo >> "$out/$cat.txt"
  done
  # drop blank lines and duplicates
  sort -u "$out/$cat.txt" | grep -v '^[[:space:]]*$' > "$out/$cat.tmp" && mv "$out/$cat.tmp" "$out/$cat.txt"
  echo "$cat: $(wc -l < "$out/$cat.txt") payloads"
}

fetch sqli \
  Fuzzing/Databases/SQLi/Generic-SQLi.txt \
  Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt \
  Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt \
  Fuzzing/Databases/SQLi/sqli.auth.bypass.txt \
  Fuzzing/Databases/SQLi/SQLi-Polyglots.txt
fetch xss \
  Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt \
  Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt
fetch traversal \
  Fuzzing/LFI/LFI-Jhaddix.txt
fetch cmdi \
  Fuzzing/command-injection-commix.txt

# ---- benign traffic the author did not choose -------------------------------
# Real English prose is the hardest false-positive test for SQLi/command
# heuristics: apostrophes, quotes, "and"/"or", semicolons, dashes.
bout="eval/external/benign"
mkdir -p "$bout"
{
  curl -fsSL --retry 3 -m 180 https://raw.githubusercontent.com/GITenberg/Pride-and-Prejudice_1342/master/1342.txt
  curl -fsSL --retry 3 -m 180 https://raw.githubusercontent.com/GITenberg/The-Adventures-of-Sherlock-Holmes_1661/master/1661.txt
} | tr -d '\r' | awk 'length($0) >= 20' | sort -u > "$bout/prose.txt"
curl -fsSL --retry 3 -m 120 "$base/Fuzzing/User-Agents/UserAgents.fuzz.txt" | tr -d '\r' | grep -v '^[[:space:]]*$' | sort -u > "$bout/user-agents.txt"
curl -fsSL --retry 3 -m 120 "$base/Discovery/Web-Content/common.txt" | tr -d '\r' | grep -v '^[[:space:]]*$' | sort -u > "$bout/web-paths.txt"
curl -fsSL --retry 3 -m 120 "$base/Usernames/Names/names.txt" | tr -d '\r' | grep -v '^[[:space:]]*$' | sort -u > "$bout/names.txt"
for f in "$bout"/*.txt; do echo "benign $(basename "$f" .txt): $(wc -l < "$f") lines"; done
