# ARIA Screenshot Inventory

Two capture sets feed the report:
1. `assets/screenshots/` — original app captures (`app_*`, `aria_*`).
2. `assets/new-screenshots/` — 27 raw captures (`Screenshot from 2026-06-12 *.png`)
   inspected and copied into `assets/screenshots/` with clean names (this pass).
3. `assets/cloud/` — Huawei Cloud console captures.

All inserted captures were checked for secrets: credential fields show
`Configured` / `Password configured` / `Replace secret` placeholders only — no
password, token, or key value is exposed. The lab host IP `193.95.30.97`
(central host) and `193.95.30.67` (vm-test) are non-credential addresses left in
place as deployment evidence; the attacker IP `209.99.188.147` in the remediation
capture is event data, not a secret.

## New captures inspected this pass (raw → clean name → destination)

| Raw timestamp | Content | Clean name | Destination |
|---|---|---|---|
| 15-36-10 | API service-root JSON (HTTP 200) | aria_api_root.png | Ch.6 §6.3 (Fig 6.2) |
| 15-37-04 | Runtime investigations list | aria_runtime_list.png | Ch.4 runtime (pair) |
| 15-37-20 | Runtime overview (observe) | aria_runtime_overview.png | Ch.4 + Ch.6 (Fig val-runtime) |
| 15-37-29 | Runtime evidence tab | aria_runtime_evidence.png | App. E.3 |
| 15-37-32 | Runtime diagnostic tab | aria_runtime_diagnostic.png | App. E.3 |
| 15-37-36 | Runtime remediation plan (no action) | aria_runtime_remplan.png | Ch.6 (Fig val-runtime) |
| 15-37-39 | Runtime verification tab | aria_runtime_verification.png | (held; context covered) |
| 15-37-45 | Runtime context tab — **chatgpt.com overlay** | — | OMITTED (overlay) |
| 15-37-51 | Runtime context (User/File/Event, T1070) | aria_runtime_context.png | App. E.3 |
| 15-37-56 | Runtime timeline tab | aria_runtime_timeline.png | App. E.3 |
| 15-38-00 | Runtime raw output tab | aria_runtime_raw.png | App. E.3 |
| 15-43-41/49/58 | ES index management (3 pages) | aria_es_indices1/2/3.png | Ch.2 (Fig ch2-es-idx) + App. E |
| 15-47-13 | Kibana Discover live stream | aria_kibana_discover.png | Ch.6 (Fig val-discover) |
| 15-57-13 | Remediation: dry-run phase | aria_rem_dryrun.png | Ch.6 (Fig val-rem) |
| 15-57-17 | Remediation: containment | aria_rem_containment.png | App. E.4 |
| 15-57-20 | Remediation: hardening (clean recap) | aria_rem_hardening.png | Ch.6 (Fig val-rem) |
| 15-57-23 | Remediation: forensics | aria_rem_forensics.png | App. E.4 |
| 15-57-27 | Remediation: verification (exit 0 + warning) | aria_rem_verification.png | App. E.4 |
| 15-57-09 | Remediation workflow thumbnail | — | OMITTED (low-res dup) |
| 16-01-17 | Archives server selector | aria_archive_selector.png | App. E (assets) |
| 16-01-33 | Assets registry (legacy/ghazi/vm-test) | aria_assets_registry.png | Ch.6 (Fig val-assets) |
| 16-02-13 | Edit server: source config (vm-test) | aria_editserver_sources.png | Ch.6 (Fig val-sources) |
| 16-02-26 | Edit server: Ansible config | aria_editserver_ansible.png | App. E (assets) |
| 16-02-53 | Ansible/remediation: Remediation Ready | aria_ansible_ready.png | Ch.6 (Fig val-assets) |

## Cloud evidence (Appendix F / Chapter 2)

- `cloud_ecs.png` — ecs-ghazi (Running) → Ch.2 Fig 2.2
- `cloud_vpc.png` — vpc-Smart_Edu topology, 10.175.1.0/24 → Ch.2 Fig 2.3 (correct hosting net)
- `cloud_eip.png` — bound Elastic IP → App. F
- `cloud_secgroup.png` — security-group rules (broad exposure noted honestly) → App. F
- `cloud_subnet.png` — **vpc-rds / 10.50.42.0/25 — WRONG hosting subnet; now UNUSED**
  (previously mis-captioned as the hosting subnet; corrected this pass).

## Layout
Main chapters: one strong capture per feature (pairs for related features).
Appendix E: compact gallery using `\pairfig` (2-up) and `\quadfig` (4-up) so the
39+ captures occupy ~9 pages with one List-of-Figures line per panel.
