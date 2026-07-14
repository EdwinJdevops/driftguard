# driftguard-cli

Command-line client for [DriftGuard](https://github.com/EdwinJdevops/driftguard).

## Install

```bash
pip install driftguard-cli
```

(Not yet published to PyPI — until then, install from source: `pip install -e ./cli` from the repo root.)

## Usage

```bash
driftguard signup --org-name "Acme Corp" --org-slug acme-corp
driftguard workspace create prod-infra --region us-east-1 --s3-bucket my-tfstate --s3-key prod/terraform.tfstate
driftguard scan trigger <workspace-id> --wait
driftguard findings list --severity critical
```

Config is stored at `~/.driftguard/config.json` (mode `0600`). Override with
`DRIFTGUARD_API_URL` / `DRIFTGUARD_API_KEY` env vars for CI use.
