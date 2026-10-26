# Project Report: AI-Augmented SOC Alert Triage Pipeline

## Objective

Demonstrate a local, AI-assisted first-pass triage workflow for synthetic Wazuh-format alerts. The pipeline asks Ollama with Llama 3.2 3B for an intent summary, a supported MITRE ATT&CK mapping, preliminary severity, and a short evidence rationale. The 3B variant is used because the installed 8B model could not load reliably on the tested 8 GB CPU-only PC.

## Design

`generate_alerts.py` writes 20 fictional examples labeled TP, FP, TN, or FN for offline benchmarking. The set includes SSH brute force (T1110), privilege escalation (T1068), suspicious process execution (T1059), unauthorized file access (T1005), port scanning (T1046), and malware-related activity (T1204). The required `alert_type` label is stripped before inference to prevent label leakage.

`prompts.py` asks for evidence-based output, treats alert content as untrusted data, prohibits unsupported inferences, and requires exact JSON keys. Benign events should use `Benign Activity` and `N/A`; unsupported ATT&CK mappings should also use `N/A`. `triage.py` requests JSON mode, validates response fields and severity values, retries one malformed or evidence-conflicting response, and canonicalizes the six requested technique names by ID. A narrow evidence policy corrects a model escalation only when the alert text explicitly states routine or approved activity; the original model suggestion is retained in results for review. Benchmark labels are saved only with results and never sent in the model prompt.

## Hallucination reduction

- Limit the model to evidence present in the alert and prohibit invented context.
- Explicitly distinguish untrusted log text from instructions.
- Permit `N/A` when evidence does not support a technique.
- Require a fixed JSON schema and validate its keys and allowed severity values.
- Remove benchmark labels from the model input to avoid leakage.
- Keep results preliminary and subject to human review.

These controls reduce ambiguity but cannot guarantee factual accuracy.

## Measurement plan and results

The project uses 5 minutes per alert as an illustrative manual-review estimate, or 100 minutes for 20 alerts. This is an assumption, not a measured user study. Measure automated wall time per alert from `output/triage_results.json`; report model warm-up and setup separately.

| Measure | Result |
|---|---|
| Manual comparison estimate for 20 alerts | 100 minutes (5 minutes per alert; assumption) |
| Automated total for 20 alerts | 436.669 seconds (7m 16.7s), warm-model run |
| Manual average per alert | 300 seconds (project assumption) |
| Automated average per alert | 21.833 seconds |

The warm-model run took about 13.7× less time than the illustrative manual estimate. A separate first cold request took 125.353 seconds including model load and inference; startup is excluded from the warm-run timing. In the final run, all 20 saved records passed output checks, and the evidence consistency policy adjusted 9 model suggestions (7 explicit benign-context corrections and 2 intent-summary corrections). This is a hybrid result, not raw model accuracy. Timing does not measure accuracy; review model suggestions and policy adjustments against the synthetic benchmark separately.

## Limitations and ethics

All sample events are synthetic and use documentation-range IP addresses. This educational prototype is not a production SOC tool, may produce incorrect summaries or mappings, and must not trigger automatic containment. Review every result before acting. Do not submit real logs or sensitive data to this project or a public repository.

Alert categories follow the requested distribution: 8 TP, 4 FP, 5 TN, and 3 FN. Across TP and FN, examples cover all six requested ATT&CK IDs. Alert formats were informed by the [Wazuh ruleset](https://github.com/wazuh/wazuh/tree/master/ruleset/rules), and technique names and IDs should be checked against [MITRE ATT&CK Enterprise techniques](https://attack.mitre.org/techniques/enterprise/).
