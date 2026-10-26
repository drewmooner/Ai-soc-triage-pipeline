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

## Threat Profile

The simulated attack types are SSH brute force (T1110), privilege escalation (T1068), suspicious process or script execution (T1059), unauthorized file access (T1005), port scanning (T1046), and malware-related user execution (T1204). They were chosen to cover common identity, privilege, execution, data access, reconnaissance, and user-driven threat behaviors, while exercising all six ATT&CK mappings required by the project. The examples are synthetic and demonstrate triage behavior; they are not a complete enterprise threat model.

## Log Sources

The pipeline uses synthetic Wazuh-format JSON alert records. Each record contains an alert `id` and `timestamp`; `rule` data (`id`, `level`, and `description`); `agent` data (`id` and `name`); the `manager` name; a `location` such as an authentication log path; event `data` such as source IP and destination user; a `full_log` message; and an `alert_type` benchmark label. The `alert_type` field is removed before inference so the model cannot use the expected TP, FP, TN, or FN answer. These are generated examples, not events collected from an actual Wazuh deployment.

## Detection Logic

The prompt asks the model to assess the activity described by the alert, use only stated evidence, and treat alert content as untrusted data rather than instructions. It provides the six requested ATT&CK mappings, requires `Benign Activity` with `N/A` technique fields for clearly routine or approved activity, and allows `N/A` when suspicious activity does not support a specific mapping. The response must use a fixed JSON schema and one of four severity values. The triage script validates that schema, retries one invalid or evidence-conflicting answer, canonicalizes known ATT&CK names by ID, and applies narrow consistency checks for explicit benign context and clear attack indicators. This is preliminary triage; it does not replace rule evaluation or analyst investigation.

## False Positive Mitigation

The prompt tells the model not to treat routine approved behavior as an attack and gives examples of benign context, including successful login during approved maintenance. The pipeline also checks a limited set of explicit routine or approval phrases in the rule description and full log. If the model escalates one of those alerts, the pipeline changes the final result to `Benign Activity`, `N/A` techniques, and Low severity, while preserving the original model suggestion in the output for review. This phrase-based check is specific to the synthetic examples and would need to be replaced or supported by trusted change, identity, and asset context in a real environment.

## Findings

The final run processed 20 synthetic alerts: 8 TP, 4 FP, 5 TN, and 3 FN. All 20 saved records passed the output checks. The evidence consistency policy adjusted 9 model suggestions: 7 for explicit benign context and 2 for mismatched intent summaries. These results demonstrate the value of validating model responses against alert evidence, but they are not a measure of raw LLM accuracy because the final results include those policy corrections. The warm-model run averaged 21.833 seconds per alert (436.669 seconds total), compared with the project's illustrative, unmeasured 5-minute-per-alert manual estimate.

## Recommendations

- Keep AI-generated triage advisory; require an analyst to verify the event evidence, severity, and ATT&CK mapping before response actions.
- Enrich alerts with trusted asset ownership, identity context, approved change windows, and related events so legitimate activity can be distinguished from attacks.
- Validate detection coverage for low-and-slow scans and other behaviors that may not trigger basic rules; tune rules using reviewed incidents and false positive feedback.
- Test prompts and evidence checks against a broader, representative dataset, and measure false positives, missed attacks, mapping quality, and latency separately.
- Keep sensitive production logs and credentials out of this demonstration; apply the organization's data handling and access controls before any real deployment.
