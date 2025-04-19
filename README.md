# SUID-Sploit-Scan | Purple Tool
```
Disclaimer / No‑Liability
This script and accompanying documentation are provided strictly for educational purposes and authorized penetration‑testing engagements.
By using or distributing these materials, you accept sole responsibility for complying with all applicable laws and rules of engagement.
The author(s) and distributor(s) disclaim all liability for any direct, indirect, or consequential damages arising from misuse.
```

## Purpose

During post‑exploitation you typically collect:
  1. the target’s kernel version
  2. a list of SUID binaries 

Feeding each binary manually into `SearchSploit` and cross‑checking `GTFOBins` is slow and error‑prone, so we make a simple script.

### What it does
1. Finds exploits matching the  kernel string
2. Loops through fed SUID binaries & gathers PoCs
3. Adds GTFOBin links when a binary maybe subject
4. (Opt.) Copies PoCs to `./exploit‑db/` for offline use
5. Produces a Markdown report you can paste straight into notes

## Usage:
```
./scan.sh <kernel‑version> [suid‑list.txt] [-m]
```

## Example:
```
# On the target shell
uname -r                           # → 4.4.0-116-generic
find / -perm -4000 -type f > /tmp/suid.txt

# Pull artefacts back (rsync, scp, pwncat‑scp, etc.)
scp user@victim:/tmp/suid.txt .

# Run the scan locally on Kali
./scan.sh 4.4.0-116-generic suid.txt -m

```

## Security & Etiquette

Exploit‑DB PoCs are for educational / authorised testing only.
