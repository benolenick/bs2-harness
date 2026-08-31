# Standing up the two lab targets from scratch

Everything below is copy-paste runnable on a Linux box with Docker + Docker Compose.
Both targets are loopback-only lab apps; nothing here opens them to the network.

## 1. OWASP crAPI (the A/B benchmark target)

crAPI is the FAIR A/B target: neither harness is tuned to it (Juice Shop is the
universal training set and MIT effectively overfits it).

### 1a. Isolated dockerd (RECOMMENDED — keeps lab storage off the root disk)

The reference setup runs crAPI on a SECOND dockerd whose storage lives on a big
disk. If you have a spare disk (mounted at /mnt/data), use it; otherwise skip 1a
and use your main daemon.

```bash
sudo mkdir -p /mnt/data/crapi/{docker-data,run}
cat <<'EOF' | sudo tee /mnt/data/crapi/daemon.json
{
  "data-root": "/mnt/data/crapi/docker-data",
  "exec-root": "/mnt/data/crapi/run/exec",
  "pidfile": "/mnt/data/crapi/run/docker.pid",
  "hosts": ["unix:///mnt/data/crapi/run/docker.sock"],
  "bridge": "none",
  "default-address-pools": [{"base": "172.31.0.0/16", "size": 24}]
}
EOF
sudo DOCKER_HOST= nohup dockerd --config-file=/mnt/data/crapi/daemon.json \
  >/mnt/data/crapi/dockerd.log 2>&1 &
# verify:
sudo DOCKER_HOST=unix:///mnt/data/crapi/run/docker.sock docker ps
```

### 1b. The crAPI stack

```bash
git clone https://github.com/OWASP/crAPI /mnt/data/crapi/repo
cd /mnt/data/crapi/repo/deploy/docker
# use the MINIMAL compose (identity + community + workshop + web + mailhog + postgres
# + mongo + redis); the full compose adds the chatbot which needs a model key
sudo -E DOCKER_HOST=unix:///mnt/data/crapi/run/docker.sock \
  docker compose -f docker-compose.minimal.yml up -d
```

### 1c. The `crapi` helper (this is what the A/B runner calls)

```bash
cat <<'EOF' | sudo tee /usr/local/bin/crapi && sudo chmod +x /usr/local/bin/crapi
#!/usr/bin/env bash
export DOCKER_HOST=unix:///mnt/data/crapi/run/docker.sock
CD=/mnt/data/crapi/repo/deploy/docker
case "${1:-status}" in
  up)      sudo -E docker compose -f "$CD/docker-compose.minimal.yml" up -d ;;
  down)    sudo -E docker compose -f "$CD/docker-compose.minimal.yml" down ;;
  restart) sudo -E docker compose -f "$CD/docker-compose.minimal.yml" restart ;;
  status|ps) sudo -E docker compose -f "$CD/docker-compose.minimal.yml" ps ;;
  logs)    shift; sudo -E docker compose -f "$CD/docker-compose.minimal.yml" logs "$@" ;;
  reset)   sudo -E docker compose -f "$CD/docker-compose.minimal.yml" down -v && sudo -E docker compose -f "$CD/docker-compose.minimal.yml" up -d ;;
  daemon-up)
    sudo DOCKER_HOST= bash -c 'nohup dockerd --config-file=/mnt/data/crapi/daemon.json >/mnt/data/crapi/dockerd.log 2>&1 &'
    echo "started; wait a few seconds then: crapi status" ;;
  *) echo "usage: crapi {up|down|restart|status|logs|reset|daemon-up}"; exit 1 ;;
esac
EOF
```

(If you skipped 1a, drop the `DOCKER_HOST=` lines and use your main daemon.)

### 1d. Verify

```bash
crapi status                     # all services up
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8888/     # 200
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8025/     # 200 (MailHog)
```

- `http://127.0.0.1:8888` — web UI + API gateway (point the harnesses here)
- `http://127.0.0.1:8025` — MailHog (OTP / password-reset emails land here; several
  challenge flows REQUIRE reading them)
- Registering a user via the UI sends a verification email to MailHog.

### 1e. Sanity ceiling (the answer key)

```bash
python3 /mnt/data/crapi/scorer/crapi_score.py     # copies: ship it with this package
# expect: 8 SOLVED / 8 auto-gradeable — that's the fresh-board sanity ceiling.
# Each SOLVED row carries the exact route + evidence: the ANSWER KEY.
```

The scorer is at `scorer/crapi_score.py` in this package — copy it next to your
crAPI install and run it there.

## 2. OWASP Juice Shop (the training canary — NOT the A/B target)

Used by the improvement loop as a daily canary. MIT overfits it; keep it out of the
fair comparison.

```bash
mkdir -p ~/juice-target && cd ~/juice-target
cat <<'EOF' > docker-compose.yml
services:
  juiceshop:
    image: bkimminich/juice-shop:latest
    container_name: juiceshop
    ports: ["127.0.0.1:3006:3000"]
  caddy:
    image: caddy:2-alpine
    container_name: juice-caddy
    ports: ["127.0.0.1:3007:80"]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
EOF
cat <<'EOF' > Caddyfile
:80 {
    reverse_proxy juiceshop:3000
}
EOF
docker compose up -d
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3006/     # 200
```

Note: Juice Shop's challenges oracle is `/api/Challenges` (an auto-gradeable
scoreboard MIT is known to be tuned against) — that is exactly why the A/B uses
crAPI, which has no auto-oracle.

## 3. Reset discipline (the fairness contract)

Between EVERY harness run: `crapi reset` (compose down -v = wipe postgres/mongo/redis
state → a genuinely fresh board). Both harnesses must face identical initial state;
run the scorer sanity check after a reset to prove the fresh board is fully
exploitable BEFORE either harness touches it.
