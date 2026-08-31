# Gunbelt Auto-Authoring — CHECKPOINT (2026-08-22)

## WHAT THIS IS
Auto-authored, BLIND, coverage-by-volume pentest card library for the gunbelt/autoturret
engine. Cards are generic firable moves; one happens to fit — never answer-baked.

## STATE
- **catalog/deck_final.yaml = 351 cards** (canonical, single source; om-b9 loads via GB_CATALOG).
  - FORMAL (machine-verifiable success_if in engine DSL): **147** (was 10).
  - PROVE-RCE landings (run `id` -> gate `uid=\d+\(` -> emit rce_as): **36**.
  - phases: recon 14, enum 156, cred 49, exploit 69, privesc 39, loot 15, lateral 9.
  - Terrain: all 6 enterprise-lab boxes — linux mail+web, Windows/AD (kerberos/ldap/smb/rdp/winrm),
    MSSQL, Squid-proxy, IIS/WebDAV, web-deep + generic heavy unauth-RCE (gitlab/struts/drupal/tomcat/jenkins/log4shell).
  - backup: catalog/deck_final.yaml.bak-preV2

## KEY ARTIFACTS
- authoring/vocab.py     — binds live Ariadne predicate/operator vocab.
- authoring/gate.py      — vocab+shape+content-blind gate; dedup_key = tool|operator|when-keys.
- authoring/author_lab.py, author_slice.py, author_full.py — codex authoring drivers (luna/terra).
- authoring/formalize.py, formalize2.py — success_if -> DSL formalizer (leads=vuln_present, landings=uid=/rce_as).
- authoring/range_spray.py — validation spray vs range box.
- tools/gitlab_22205_inband.py — callback-free CVE-2021-22205 (msf-exact DjVu payload; writes id to
  gitlab public webroot, reads inline; no egress). Deployed on your-host + your-host.

## VALIDATION
- Range box **192.0.2.10** (your-host redzone, ip alias on virbr-red): ftp/ssh:2222/smtp/dvwa:8081/
  samba/wordpress:8080 + mssql:1433/ldap:389/squid:3128. Ground-truth flags in ftp+smb shares.
- Blind spray: 157/301 cards matched terrain unseen; 19 recon/enum fired clean; ZERO false-positives
  (anon-FTP cards correctly refused a weak-cred-only box).
- LIVE (om-b9 engine vs HTB box): autonomously grounded 2 flags + ftp-anon + 11 vhosts + drupal/wp/gitlab
  apps. owned=false (reverse-shell egress-blocked -> callback-free gitlab card shipped for re-run).

## INTEROP WITH om-b9 (autoturret engine)
- confirms: -> Ariadne predicates (planner). verify.emits: -> engine fact-keys via bridge EMIT_ALIAS
  {rce_as->shell, controls_principal->cred, has_hash->hash}. Grounding proof: uid=\d+\( for shell.
- Split: I formalize exploit/privesc/cred gates; om-b9 runs deepseek LLM-judge for prose recon/enum tail.
- om-b9 stack live: autoturret + flash trooper + Ariadne + Memoria RAG(:8009, 6.8M vec) + governed ledger.

## OPEN / NEXT (ranked)
1. Break dedup throttle -> intra-technique variation survives (4-8x, cheap).       [biggest immediate]
2. Memoria giga-tail: attach recipes to ~760k exploit facts (hundreds of thousands). [the 1000x leap]
3. Post-exploit/privesc depth (GTFOBins/SUID/sudo/kernel/cron/container-escape).
4. More terrain: cloud/k8s/postgres/redis/mongo/elastic/SNMP.
5. Vuln-target matrix (vulhub) -> promote cards gated->proven (efficacy, not just fireability).
6. Self-improvement flywheel: harvest grounded chains back into authored cards.
7. Formalize remaining ~204 prose gates (mostly enum/recon).
- AWAITING: om-b9 "uid= grounded" ping on the inband GitLab foothold (live box 198.51.100.10).
