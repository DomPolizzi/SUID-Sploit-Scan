#!/usr/bin/bash
# Usage: ./scan.sh <kernel‑version> [suid‑list.txt] [-m]

set -euo pipefail
msg(){ printf '\e[1;36m[+] %s\e[0m\n' "$*"; }
err(){ printf '\e[1;31m[!] %s\e[0m\n' "$*" >&2; exit 1; }

[[ $# -lt 1 ]] && err "Syntax: $0 <kernel‑version> [suid‑list.txt] [-m]"

KERNEL="$1"; shift
LIST="${1:-}"; [[ $# -gt 0 && "$1" != "-m" ]] && shift || true
COPY=0; [[ "${1:-}" == "-m" ]] && COPY=1

[[ -n "$LIST" && ! -f "$LIST" ]] && err "Cannot find list file $LIST"

if [[ -z "$LIST" ]]; then
  msg "No SUID list provided—running find (needs root)…"
  LIST="$(mktemp)"
  sudo find / -perm -4000 -type f 2>/dev/null | sort -u >"$LIST"
fi
mapfile -t SUIDS <"$LIST"

REPORT="suid-scan-REPORT.md"; : > "$REPORT"
KEYWORDS='priv|root|local|bypass|rce'

# ---------- kernel exploits --------------------------------------------------
msg "Searching kernel‑specific exploits for $KERNEL"
searchsploit -t --json "Linux Kernel $KERNEL" |
  jq -r --arg re "$KEYWORDS" '
     .RESULTS_EXPLOIT[]
     | select(.Title|test($re;"i"))
     | "• ["+.Title+"]("+"https://www.exploit-db.com/exploits/"+(.["EDB-ID"] // .ID)+")"
  ' | tee -a "$REPORT"
echo -e "\n---\n" >>"$REPORT"

# ---------- per‑binary exploits ---------------------------------------------
for BINPATH in "${SUIDS[@]}"; do
  BIN="$(basename "$BINPATH")"
  msg "Checking $BIN  ($BINPATH)"

  searchsploit --json -t "$BIN" |
    jq -r --arg re "$KEYWORDS" '
       .RESULTS_EXPLOIT[]
       | select(.Title|test($re;"i"))
       | "* ["+.Title+"]("+"https://www.exploit-db.com/exploits/"+(.["EDB-ID"] // .ID)+")"
    ' | tee -a "$REPORT"

  if curl -s --head "https://gtfobins.github.io/gtfobins/$BIN/" | grep -q '200 OK'; then
     printf '* [%s @ GTFOBins](https://gtfobins.github.io/gtfobins/%s/)\n' "$BIN" "$BIN" | tee -a "$REPORT"
  fi
  echo >>"$REPORT"

  (( COPY )) && searchsploit -m "$BIN" >/dev/null 2>&1 || true
done

msg "Done. Report in $REPORT"
(( COPY )) && msg "PoCs copied to ./exploit-db/"
