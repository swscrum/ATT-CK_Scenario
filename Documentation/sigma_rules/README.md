# Sigma rule pack — Waystar Royco lab

Sigma rules (platform-neutral detection format) that cover the most
reliable signals produced by the auto-chain. Import these into your
SIEM's Sigma rule loader (Wazuh, Splunk Sigma App, Elastic Detection
Engine, Loki+SigmaToLoki, Chronicle, etc.) and the analyst will see
alerts firing during a `--pacing realistic` run.

## What's here (initial 5)

| Rule | MITRE | Source log | Confidence |
|---|---|---|---|
| `apache_cve_2021_41773_traversal.yml` | T1190 | apache access.log | high (URL pattern is unmistakable) |
| `lab_fim_cleanup_sh_modified.yml` | T1053.003 | apache lab-fim.log | high (cleanup.sh modified by anyone but the sysadmin process == foul play) |
| `sshd_failed_password_burst.yml` | T1110.004 | workstation/luke_ws/vinzenz_ws auth.log | medium (same-src 3+ failures in 60s) |
| `sshd_lateral_via_apache.yml` | T1021.004 | workstation auth.log + router NFLOG | high (apache should not SSH to the workstation in normal ops) |
| `nflog_dmz_scan_internal_ssh.yml` | T1018 + T1046 | router NFLOG | high (apache 10.40.0.2 sweeping the 10.30.0.0/24 :22 space is anomalous) |

Each rule maps to a row in [`../mappings.md`](../mappings.md) — extend
that table first, then write a matching Sigma file here when a new
technique lands. One file per technique keeps individual rules easy to
tune.

## Conventions

- **`title`** mirrors `<technique>: <human-readable summary>`.
- **`level`** is `medium` or `high` only — leave `low` for future
  behavioural heuristics that haven't been validated yet.
- **`tags`** include the MITRE tactic + technique IDs in
  `attack.<tactic>` / `attack.<technique>` form so SIEMs that auto-route
  by tag (Splunk, Wazuh) Just Work.
- **`falsepositives`** lists what the noise_user_sim container will
  legitimately trigger, so a tuner knows what to whitelist.
- **`logsource`** uses `category: webserver` / `category: firewall` /
  `category: file_event` / `service: sshd` — the standard Sigma
  taxonomy so backends translate cleanly.

## Verifying a rule fires

1. Run `tools/run.sh --pacing realistic --keep-up` end to end.
2. Ingest `Infrastructure/logs/run-<ts>/**/*.diurnal.log` into your SIEM.
3. The rule should fire at least once per chain run. If it doesn't, the
   either the SIEM's field extraction is misnamed (most common) or the
   chain produced no matching event (check `chain-<ts>.json` to confirm
   the step ran).

## What's NOT here (intentionally)

- Anything for the quiet later-phase beats (key theft, exfil staging,
  ransomware). These need EDR / process-execve telemetry the lab
  doesn't currently produce. When `auditd` lands (or when we get an
  in-lab EBPF agent), add rules for them.
- Vendor-specific rules. Sigma is the contract; backend translation is
  the SIEM operator's job.
