# Deploying horkos-oss on a server

Dependency-free, so deployment is just "install the package, run two commands":
`horkos-scan` (run an observe-only scan from a config) and `horkos-web` (serve the
dashboard). Pick bare-metal/systemd or Docker.

> Authorization is yours: a scan runs only when its config sets `"authorized": true`,
> and only against programs whose policy permits automated scanning. See `LAUNCH.md`.

## Bare metal (Ubuntu + systemd)

```bash
sudo useradd -r -m -d /opt/horkos-oss horkos
sudo -u horkos python3 -m venv /opt/horkos-oss/venv
sudo -u horkos /opt/horkos-oss/venv/bin/pip install git+https://github.com/LordHorkos/horkos-oss
sudo -u horkos mkdir -p /opt/horkos-oss/{runs,configs}

# one config per engagement
sudo -u horkos cp deploy/scan.config.example.json /opt/horkos-oss/configs/acme.json
# edit it: set authorized=true after confirming the program, fill scope + seeds

# dashboard service (localhost:8787, read-only)
sudo cp deploy/horkos-dashboard.service /etc/systemd/system/
sudo systemctl enable --now horkos-dashboard

# scheduled scans (templated per config name)
sudo cp deploy/horkos-scan@.service deploy/horkos-scan@.timer /etc/systemd/system/
sudo systemctl enable --now horkos-scan@acme.timer      # runs configs/acme.json daily
sudo systemctl start horkos-scan@acme.service           # or run once now
```

The dashboard binds to `127.0.0.1`. If you expose it beyond the box, put it behind
your own reverse proxy **with authentication** — the app has no auth of its own
(it's a local tool).

## Docker

```bash
docker build -t horkos-oss -f deploy/Dockerfile .
docker volume create horkos-runs

# serve the dashboard (published only to localhost on the host)
docker run -d --name horkos-web -p 127.0.0.1:8787:8787 \
  -v horkos-runs:/data/runs horkos-oss

# run a scan into the same volume
docker run --rm -v horkos-runs:/data/runs \
  -v $PWD/configs:/app/configs horkos-oss \
  horkos-scan --config /app/configs/acme.json
```

## Lab validation first

Before a real program, prove the pipeline against a local vulnerable target
(`resolve_allow_private` lets it reach loopback):

```bash
horkos-scan --config lab.json --allow-private
```

## What a run produces

Each run writes to its `out_dir`: `run.json` (dashboard manifest), `report.md`,
`dashboard.html`, `audit.jsonl` (verify with `AuditLog.verify`), and `evidence/`.
`horkos-web` lists every run under the runs root and renders each on demand.
