## Reformulation Depth Limit (server-enforced)

`reason.evaluate_finding` is rate-limited per finding-description. If the same normalized description has been evaluated 2 times recently with no new tool calls between attempts, the third is refused with gate `reformulation_depth_limit`. Remediation:
1. Run new tool calls for fresh evidence before re-evaluating, OR
2. Park as UNCONFIRMED (note the reformulation loop) and pursue a different finding direction.

Intent: prevent rumination spirals where the agent defends a finding via wording changes instead of better evidence.

---
