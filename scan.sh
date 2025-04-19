#!/usr/bin/bash
# Usage: ./scan.sh <kernel‑version> [suid‑list.txt] [-m]

set -euo pipefail
msg(){ printf '\e[1;36m[+] %s\e[0m\n' "$*"; }
err(){ printf '\e[1;31m[!] %s\e[0m\n' "$*" >&2; exit 1; }

[[ $# -lt 1 ]] && err "Syntax: $0 <kernel-ver> [suid-list] [-m]"
KERNEL="$1"; shift
LIST="${1:-}"; [[ $# -gt 0 && "$1" != "-m" ]] && shift || true
COPY=0; [[ "${1:-}" == "-m" ]] && COPY=1
[[ -n "$LIST" && ! -f "$LIST" ]] && err "Cannot find list file $LIST"

# ---------- derive helpers ---------------------------------------------------
MAJOR="${KERNEL%%.*}"                                          # 4
MAJMIN="$(echo "$KERNEL" | cut -d- -f1 | cut -d. -f1-2)"       # 4.4

# ---- distro keyword helper mappings (expand/trim as needed) -----------------
declare -A DISTRO_MAP=(
  # Ubuntu
  ["4.4"]="Ubuntu 16"
  ["4.8"]="Ubuntu 16.10"
  ["4.15"]="Ubuntu 18"
  ["5.4"]="Ubuntu 20"
  ["5.15"]="Ubuntu 22"

  # Debian
  ["4.19"]="Debian 10"
  ["5.10"]="Debian 11"
  ["6.1"]="Debian 12"

  # RHEL / CentOS / Alma / Rocky
  ["3.10"]="CentOS 7"   # RHEL 7 family
  ["4.18"]="CentOS 8"   # RHEL 8 family
  ["5.14"]="CentOS 9"   # RHEL 9 family
)
DISTRO_QUERY=""
[[ -n "${DISTRO_MAP[$MAJMIN]:-}" ]] \
  && DISTRO_QUERY="linux kernel ${DISTRO_MAP[$MAJMIN]} Local Privilege Escalation"

REPORT="Purple-REPORT.md"; : >"$REPORT"
KEYWORDS='priv|root|local|bypass|rce'

# ---------- helper: filtered SearchSploit -----------------------------------
run_query () {
  local QUERY="$1"
  searchsploit -t --json "$QUERY" | \
    jq -r \
       --arg kw   "$KEYWORDS" \
       --arg maj  "$MAJOR"    \
       --arg mm   "$MAJMIN"   '
      .RESULTS_EXPLOIT[]
      | select(.Title|test($kw;"i"))
      | select(.Title|test($maj + "\\."; "i"))
      | select(.Title|test("< *" + $mm;"i") | not)
      | "* ["+.Title+"]("+"https://www.exploit-db.com/exploits/"+(.["EDB-ID"] // .ID)+")"
    '
}

# ---------- collect / build SUID list ---------------------------------------
if [[ -z "$LIST" ]]; then
  msg "No SUID list supplied—enumerating (needs root)…"
  LIST="$(mktemp)"
  sudo find / -perm -4000 -type f 2>/dev/null | sort -u >"$LIST"
fi
mapfile -t SUIDS <"$LIST"

# ---------- kernel‑centric searches -----------------------------------------
msg "Exact kernel exploits for $KERNEL"
run_query "Linux Kernel $KERNEL" | tee -a "$REPORT"; echo >>"$REPORT"

msg "Broad kernel exploits for $MAJMIN.x"
run_query "Linux Kernel $MAJMIN" | tee -a "$REPORT"; echo >>"$REPORT"

if [[ -n "$DISTRO_QUERY" ]]; then
  msg "Distro‑helper search: $DISTRO_QUERY"
  run_query "$DISTRO_QUERY" | tee -a "$REPORT"; echo >>"$REPORT"
fi
echo -e "---\n" >>"$REPORT"

# ---------- per‑binary scan --------------------------------------------------
for BINPATH in "${SUIDS[@]}"; do
  BIN="$(basename "$BINPATH")"
  msg "Checking $BIN"
  printf "### %s (%s)\n" "$BINPATH" "$BIN" >>"$REPORT"

  run_query "$BIN" | tee -a "$REPORT"

  if curl -s --head "https://gtfobins.github.io/gtfobins/$BIN/" | grep -q '200 OK'; then
    printf '* [%s @ GTFOBins](https://gtfobins.github.io/gtfobins/%s/)\n' "$BIN" "$BIN" | tee -a "$REPORT"
  fi
  echo >>"$REPORT"

  (( COPY )) && searchsploit -m "$BIN" >/dev/null 2>&1 || true
done

msg "Finished → $REPORT"
(( COPY )) && msg "PoCs copied into ./exploit-db/"
