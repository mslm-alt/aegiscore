# Behavioral ML Support Architecture

## Purpose

AegisCoreSIEM keeps rule detection as the primary detection and action layer.

- Rule layer catches known attacks and drives detection and action behavior.
- ML is a support layer for user and host behavior profiling.
- ML does not replace rules.
- ML does not take attack detection ownership away from the rule layer.

## Hard boundaries

Behavioral ML must not:

- suppress or alter a rule alert
- raise or lower risk score
- trigger IP block, firewall, or incident action
- close or resolve incidents
- enable active response
- write labels into the database from this manifest flow
- enable active training
- emit alerts outside the ML anomaly family surface

Behavioral ML must keep:

- `no_action_contract=true`
- `active_training_enabled=false`
- read-only manifest and audit commands
- rule-backed family mapping from `rule_id` to `ml_family` and `ml_label`

## ML output contract

The verified manifest path is a read-only labeling surface for candidate generation and audit.

- Input: live `events_recent` and `alerts` snapshots, read-only.
- Families: `ML-AUTH`, `ML-PROC`, `ML-IMPACT`.
- Output: candidate metadata, evidence summary, family summaries, and safe audit results.
- Safety: no DB write, no training, no evaluation, no alert emit.

## Auto-label disposition

There is no human decision workflow in this path.

- `direct_learnable`: strong rule-backed candidate with enough evidence and clean duplicate/dominance posture.
- `ignored`: useful but weak, partial, or ambiguous behavioral signal that does not enter learning.
- `rejected`: generic noise, unsupported family shape, malformed identity, or duplicate-heavy candidate.

`disposition` describes label quality only. It does not change runtime detection, correlation, risk, or guarded actions.

## Family intent

`ML-AUTH`

- learns login rhythm, active hours, identity usage patterns, and auth attempt cadence

`ML-PROC`

- learns process, command, sudo/root, service, and maintenance behavior habits

`ML-IMPACT`

- tracks destructive or tamper-like behavior patterns only when rule-backed evidence exists

## Example ML anomaly logic

Behavioral ML can highlight patterns such as:

- a user being active outside their normal hours
- a user performing unusually heavy `sudo` or root activity
- an unusual process appearing on a host that normally does not run it
- a slow brute-force pattern drifting away from the account or host's normal auth rhythm

These ML observations remain advisory. They do not trigger IP block, firewall action, incident closure, risk changes, or any other active response.

## Safe operator surface

These commands remain safe and supported:

- `python main.py --ml-verified-manifest-dry-run`
- `python main.py --ml-verified-manifest-audit <manifest.json>`
- `python main.py --ml-summary`
- `python main.py --ml-readiness`
- `python main.py --ml-mapping-audit`

These commands are informational only. They do not enable active ML or change runtime state.
