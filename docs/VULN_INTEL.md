# Passive Vulnerability Intelligence

Version: `v2.4.0-vuln-intel`

This layer answers the NVD-enrichment problem from the CVE transcript: the
pipeline should not treat NVD as the complete truth source. It should normalize
multiple public vulnerability signals, match them to assets already in local
Elasticsearch, and only then feed safe review and scoring.

## Data Flow

1. `recon_cve_intel.sh` keeps the existing KEV/NVD baseline.
2. `recon_vuln_feed.sh` normalizes vulnerability signals into
   `~/recon/vuln/vuln_feed.jsonl`.
3. The same script matches non-`T3` records to local ES tech fingerprints and
   writes `~/recon/vuln/vuln_targets.jsonl`.
4. `recon_brain.sh` refreshes the vuln feed before triage.
5. The daemon runs `vuln-feed` automatically every hour by default.

## Inputs

- CISA KEV from the existing local `~/recon/cve/kev.json`.
- Recent NVD from the existing local `~/recon/cve/nvd_recent.json`.
- Optional EPSS current CSV.
- Optional CISA Vulnrichment recent GitHub activity.
- Optional ProjectDiscovery nuclei-template CVE index and latest release notes.

If optional feeds fail, the layer keeps working from local KEV/NVD data and
tries again on the next daemon cycle.

## Outputs

- `~/recon/vuln/summary.json`: counts by tier and source.
- `~/recon/vuln/vuln_feed.jsonl`: normalized vulnerability records.
- `~/recon/vuln/vuln_targets.jsonl`: passive local ES asset matches.

These are derived queues. A fresh ES reset archives/clears derived target
queues so old matches do not pollute a clean restart.

## Safety Rules

- This layer is passive intelligence only.
- It does not run nuclei.
- It does not probe targets.
- It does not let AI-created templates run automatically.
- Worker execution stays under `reconrun`; the nftables kill switch and Tor
  proxy model remain the security boundary.

## Commands

```bash
~/recon-pipeline/scripts/recon_ctl.sh vuln status
~/recon-pipeline/scripts/recon_ctl.sh vuln top
~/recon-pipeline/scripts/recon_ctl.sh v2 refresh-vuln
~/recon-pipeline/scripts/recon_ctl.sh health
```

Discord:

```text
!vuln
!health
```
