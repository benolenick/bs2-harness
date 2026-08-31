# Recon brief — HTB box 198.51.100.10 (authorized HTB lab target, VPN tun0 up)

You are a bounded recon executor. Do ONLY recon/enumeration. No exploitation, no writes to the target.

TASKS (run these, in order):
1. `nmap -Pn --min-rate 2000 -p- -T4 198.51.100.10 -oN nmap-allports.txt`  (full TCP port sweep)
2. From the open ports, run `nmap -Pn -sC -sV -p <comma-open-ports> 198.51.100.10 -oN nmap-services.txt`
3. If 80/443/8080/other HTTP open: `curl -sSik http://198.51.100.10/ | head -60` and `whatweb http://198.51.100.10/ 2>/dev/null || true`. Note server header, title, any CMS/framework.
4. If SMB (445): `nmap --script smb-os-discovery,smb-enum-shares -p445 198.51.100.10 -oN nmap-smb.txt || true`

Then WRITE two files in this directory:
- `map.json` — EXACTLY this schema (the gunbelt loader consumes it):
  {"hosts":[{"ip":"198.51.100.10","is_dc":false,"ports":[{"port":80,"name":"http","product":"Apache httpd 2.4.41"}, ...],"services":["http","ssh"]}],"creds":[]}
- `FINDINGS.md` — 8-line human summary: OS guess, every open port+service+version, the single most likely attack surface, and your one-line guess at the box's PRIMARY CATEGORY (web-app / AD-windows / linux-service / cms / database / etc).

Be fast and factual. Do not speculate beyond what the scans show.
