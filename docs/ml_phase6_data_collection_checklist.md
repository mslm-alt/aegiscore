# Phase 6B: Behavioral ML Data Collection Checklist

## Scope and safety

This checklist exists to improve evidence quality for the behavioral ML support layer.

- Rule detection remains the primary detection and action layer.
- ML does not change rule alerts, risk scores, firewall state, or incident actions.
- No DB label writes.
- No source event correction.
- No `events_recent` or `alerts` updates.
- No training, evaluation, alert emit, or active ML enablement.
- `active_training_enabled=false` stays locked.
- `no_action_contract=true` stays locked.

## Auto-label disposition policy

Verified manifest candidates use automatic disposition only:

- `direct_learnable`: strong `rule_id` mapping, enough base fields, duplicate/dominance clean.
- `ignored`: weak or ambiguous rule support, incomplete or low-confidence evidence that stays out of learning.
- `rejected`: generic noise, unsupported family shape, duplicate-heavy, or very incomplete data.

The goal is not to replace rule detections. The goal is to produce clean, read-only ML support labels for `ML-AUTH`, `ML-PROC`, and `ML-IMPACT`.

## AUTH checklist

Goal: improve user/login behavior evidence quality without inventing context.

- Native `src_ip` is collected from the source event when present.
- Session identifier is present when available.
- Remote peer or remote host is present when available.
- `context_json` contains IP or peer detail when event-native fields are absent.
- `alert_entity` can be matched back to the event without relying only on time proximity.
- PAM/auth subsystem source detail is present.
- Auth outcome detail is normalized across success, failure, open, and close.
- Host identity is normalized consistently.
- Actor vs target identity is distinguishable.
- TTY or terminal origin is preserved when relevant.

Collection priority:

- Highest: native `src_ip`, remote peer, session id.
- Next: PAM source detail, stronger alert/event linkage, normalized host and outcome fields.

Disposition impact:

- Strong rule-backed auth evidence can become `direct_learnable`.
- Missing native `src_ip` or weak bridge quality should stay `ignored` or `rejected`.
- Candidate-level inference does not replace source evidence.

## PROC checklist

Goal: improve process and service habit learning without relaxing generic-noise filters.

- `process` or executable identity is populated.
- Parent process is captured.
- Command line or exec context is readable.
- Generic syscall-only artifacts are filtered or clearly separable.
- Browser/UI background noise is filtered or clearly separable.
- Cron-like benign examples exist.
- Service-like benign examples exist.
- Package-management or maintenance benign examples exist.
- Username and host are normalized consistently.
- Suspicious process candidates can be linked to rule hints or supporting alert context.

Collection priority:

- Highest: process identity, parent process, command/exec context.
- Next: better benign diversity and stronger suspicious alert linkage.

Disposition impact:

- Strong process-backed evidence can become `direct_learnable`.
- Discovery-like or partially supported behavior should remain `ignored`.
- Generic syscall and browser/UI noise should remain `rejected`.

## ML-IMPACT checklist

Goal: collect only rule-backed tamper or destructive behavior evidence, not generic file access noise.

- DE/tamper rule-backed examples exist.
- Log clearing or truncation examples exist.
- Security service stop/disable examples exist.
- Destructive command examples exist.
- Supporting alert linkage exists.
- Event-to-alert or incident bridge is specific and readable.
- Generic `file_access` remains separately rejected.
- Tamper semantics are visible in the excerpt or correlated context.
- Host, actor, and target context are normalized.

Collection priority:

- Highest: DE/tamper-backed samples with supporting alert linkage.
- Next: log-clearing, service-disable, and destructive-command coverage.

Disposition impact:

- Only strong tamper/destructive evidence should reach `direct_learnable`.
- Partial or weak evidence should stay `ignored`.
- Generic `file_access` must stay `rejected`.

## Operating conclusion

Phase 6B data collection improves the evidence feeding the behavioral ML support layer. It does not authorize runtime ML activation, rule suppression, event mutation, risk changes, or any active response.
