# CARD: appcve  (named-app version fingerprint -> matching public CVE runner)
Read CONTRACT.md first. Write the card to /opt/bs2/live/cards/appcve.py exposing fire(rx, lane).

Detect: identify a named web app AND its exact version from its OWN version surface (e.g. a
/help, /api/*/version, meta generator tag, changelog, or login-page version string), honoring
rx._hh() and iterating rx.vhosts. Support a GENERAL, extensible table of {app -> [(version_range,
cve_id, exploit_fn)]} covering common enterprise apps (GitLab, Confluence, Jenkins, Drupal, Joomla,
Grafana, etc.). This is general vuln intelligence (like searchsploit), keyed on the DETECTED
version — never on which host it is.
Exploit: if the detected version falls in a known-vulnerable range, run that CVE's PUBLIC
unauthenticated (preferred) command-exec technique to run `id`.
Verify: success only on grounded command output (`uid=` or the app-specific proof). Facts:
`app=<name>:<label>`, `finding=<cve_id>@<app>`, `rce_as=<user>`/`shell=<user>`, any flag printed.
Fail safe: no version match -> return None.
Keep the version->CVE table in-file and easy to extend. NO target-specific literals; cover many
apps/versions, not one.
