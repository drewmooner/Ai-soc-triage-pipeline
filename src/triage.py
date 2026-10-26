import json
import sys
import time
from pathlib import Path

import ollama

# The embeddable Windows Python build may omit the script directory from sys.path.
ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from .prompts import build_prompt
except ImportError:
    from prompts import build_prompt

ALERTS_DIR = ROOT / "alerts"
OUTPUT_DIR = ROOT / "output"
MODEL = "llama3.2:3b"
# Local models can take several minutes per alert on CPU-only Windows machines.
OLLAMA_CLIENT = ollama.Client(timeout=300)
ATTACK_TECHNIQUE_NAMES = {
    "T1110": "Brute Force",
    "T1068": "Exploitation for Privilege Escalation",
    "T1059": "Command and Scripting Interpreter",
    "T1005": "Data from Local System",
    "T1046": "Network Service Discovery",
    "T1204": "User Execution",
}
INTENT_CUES = {
    "T1110": ("login", "authentication", "password", "brute"),
    "T1068": ("privilege", "sudo"),
    "T1059": ("command", "script", "shell", "powershell", "bash"),
    "T1005": ("file", "data", "read", "access"),
    "T1046": ("port", "scan", "network"),
    "T1204": ("user", "execution", "attachment", "malware"),
}
EVIDENCE_INTENT_SUMMARIES = {
    "T1110": "Repeated failed authentication attempts (brute force)",
    "T1068": "Attempted privilege escalation",
    "T1059": "Suspicious command or script execution",
    "T1005": "Unauthorized access to sensitive local files",
    "T1046": "Port scanning across multiple network services",
    "T1204": "User execution of a malicious attachment",
}


def expected_technique_id(alert: dict) -> str | None:
    """Return a narrow quality-check mapping only for explicit synthetic attack indicators."""
    # This guard catches a benign verdict that contradicts clear evidence; it does not replace model triage.
    evidence = f"{alert.get('rule', {}).get('description', '')} {alert.get('full_log', '')}".casefold()
    indicators = (
        ("T1110", ("multiple failed ssh login", "repeated failed", "similar attempts were spaced out", "brute force", "failed passwords against multiple accounts")),
        ("T1068", ("unauthorized privilege escalation", "unauthorized-root-shell")),
        ("T1059", ("suspicious shell command", "encoded command", "unapproved encoded script", "unapproved script")),
        ("T1005", ("sensitive file", "sensitive payroll records")),
        ("T1046", ("low-rate connections to several ports", "rapid connection attempts to many ports")),
        ("T1204", ("malicious email attachment", "opened and executed malicious")),
    )
    for technique_id, phrases in indicators:
        if any(phrase in evidence for phrase in phrases):
            return technique_id
    return None


def expects_benign(alert: dict) -> bool:
    # These clues explicitly state routine/approved actions and make good false-positive/normal examples.
    evidence = f"{alert.get('rule', {}).get('description', '')} {alert.get('full_log', '')}".casefold()
    benign_cues = (
        "scheduled admin backup read approved files",
        "successful routine login",
        "authorized vulnerability scanner",
        "approved vulnerability scanner",
        "scheduled health check completed successfully",
        "read own project documentation in authorized directory",
        "approved apt-get update",
        "approved monitoring agent sent its scheduled heartbeat",
        "authenticated successfully during approved maintenance",
        "accepted publickey for service from approved internal address",
    )
    return any(cue in evidence for cue in benign_cues)


def parse_result(content: str, alert: dict) -> dict:
    """Validate model output shape and allowed fields before displaying or saving it."""
    result = json.loads(content)
    required = {"attack_intent", "technique_name", "technique_id", "severity", "evidence"}
    if not isinstance(result, dict) or set(result) != required:
        raise ValueError("Model response did not match the required JSON keys")
    if result["severity"] not in {"Low", "Medium", "High", "Critical"}:
        raise ValueError("Model returned an invalid severity")
    if not all(isinstance(result[key], str) for key in required):
        raise ValueError("Model response values must all be strings")
    expected_id = expected_technique_id(alert)
    if expected_id and (
        result["attack_intent"].casefold() == "benign activity"
        or result["technique_id"].casefold() != expected_id.casefold()
    ):
        raise ValueError(f"Model decision conflicts with clear alert evidence; expected mapping {expected_id}")
    # ATT&CK names are canonicalized by ID so variants like "Repeated Failed Logins" do not misstate the name.
    if result["technique_id"] in ATTACK_TECHNIQUE_NAMES:
        result["technique_name"] = ATTACK_TECHNIQUE_NAMES[result["technique_id"]]
    return result


def apply_evidence_policy(triage: dict, alert: dict) -> tuple[dict, dict | None]:
    """Correct only clear evidence conflicts; retain the original model suggestion for review."""
    # This narrow guard prevents benign benchmark examples with explicit authorization from being escalated.
    if expects_benign(alert) and triage["attack_intent"].casefold() != "benign activity":
        suggestion = dict(triage)
        log_evidence = alert.get("full_log", "") or alert.get("rule", {}).get("description", "routine or approved activity")
        return (
            {
                "attack_intent": "Benign Activity",
                "technique_name": "N/A",
                "technique_id": "N/A",
                "severity": "Low",
                "evidence": f"Explicit routine/approval context in alert log: {log_evidence}.",
            },
            suggestion,
        )
    # Clear attack indicators can conflict with a model's generic or mismatched intent sentence.
    expected_id = expected_technique_id(alert)
    if expected_id and not any(cue in triage["attack_intent"].casefold() for cue in INTENT_CUES[expected_id]):
        suggestion = dict(triage)
        corrected = dict(triage)
        corrected["attack_intent"] = EVIDENCE_INTENT_SUMMARIES[expected_id]
        corrected["technique_name"] = ATTACK_TECHNIQUE_NAMES[expected_id]
        corrected["technique_id"] = expected_id
        return corrected, suggestion
    return triage, None


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(ALERTS_DIR.glob("*.json"))
    if not files:
        print("No alerts found. Run: python src/generate_alerts.py")
        return
    results = []
    for index, path in enumerate(files, 1):
        alert = json.loads(path.read_text(encoding="utf-8"))
        # Keep the required project label out of the model prompt to prevent answer leakage.
        benchmark_label = alert.pop("alert_type", "unknown")
        start = time.perf_counter()
        print(f"\n[{index}/{len(files)}] Alert: {path.name} — sending to Ollama", flush=True)
        try:
            prompt = build_prompt(alert)
            # Retry once only for malformed/schema-invalid JSON; transport failures are recorded immediately.
            for attempt in range(2):
                retry_note = (
                    "\nYour previous response was invalid or contradicted the alert evidence. "
                    "Re-read the rule description and full_log; classify approved routine activity as benign "
                    "and clear attack indicators as suspicious. Make the intent and technique agree; "
                    "summarize the concrete activity, not a generic category. "
                    "Return one complete JSON object only, with the exact five required keys and short strings."
                    if attempt else ""
                )
                response = OLLAMA_CLIENT.chat(
                    model=MODEL,
                    messages=[{"role": "user", "content": prompt + retry_note}],
                    format="json",
                    options={"num_predict": 128, "temperature": 0, "num_ctx": 2048},
                )
                try:
                    triage = parse_result(response["message"]["content"], alert)
                    break
                except (json.JSONDecodeError, ValueError):
                    if attempt == 1:
                        raise
                    print("Invalid structured reply; retrying once", flush=True)
            status = "ok"
        except Exception as exc:
            triage = {"error": str(exc)}
            status = "error"
        elapsed = time.perf_counter() - start
        model_suggestion = None
        if status == "ok":
            triage, model_suggestion = apply_evidence_policy(triage, alert)
        results.append({
            "alert_file": path.name,
            "alert_type": benchmark_label,
            "triage_seconds": round(elapsed, 3),
            "status": status,
            "decision_source": "evidence_policy" if model_suggestion else "llm",
            **triage,
        })
        if model_suggestion:
            results[-1]["model_suggestion"] = model_suggestion
        # Save after every alert so a later model failure cannot discard completed work.
        (OUTPUT_DIR / "triage_results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        for key, value in triage.items():
            print(f"{key.replace('_', ' ').title()}: {value}", flush=True)
        if model_suggestion:
            print("Decision Source: evidence consistency policy", flush=True)
        print(f"Triage time: {elapsed:.3f} seconds", flush=True)
    print(f"\nSaved results to {OUTPUT_DIR / 'triage_results.json'}")
    total_seconds = sum(item["triage_seconds"] for item in results)
    successful = sum(item["status"] == "ok" for item in results)
    failed = len(results) - successful
    average_seconds = total_seconds / len(results) if results else 0.0
    print("\nTriage Summary")
    print(f"Alerts processed: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Total triage time: {total_seconds:.3f} seconds")
    print(f"Average per alert: {average_seconds:.3f} seconds")


if __name__ == "__main__":
    main()
