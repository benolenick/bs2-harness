# CARD: werkzeug  (Flask/Werkzeug interactive debugger -> RCE)
Read CONTRACT.md first. Write the card to /opt/bs2/live/cards/werkzeug.py exposing fire(rx, lane).

Detect: fingerprint Werkzeug — a `Server: Werkzeug/...` response header, or an unhandled-exception
traceback page containing "Werkzeug Debugger" / "console-locked" / a `__traceback__` token. Probe a
few paths and a deliberately-bad request to trigger a traceback, honoring rx._hh().
Exploit: if the debugger console is OPEN (no PIN), POST to the console eval endpoint to run
`__import__('os').popen('id').read()`. If PIN-locked, attempt the standard Werkzeug PIN derivation
only from data you can read remotely (do NOT fabricate host secrets); if the needed inputs are not
obtainable, return None (defer to trooper) rather than guessing.
Verify: success only on `uid=` in the eval output. Facts: `finding=werkzeug-debug@<path>`,
`rce_as=<user>`, `shell=<user>`.
Fail safe: no Werkzeug debugger evidence -> return None. NO target-specific literals.
