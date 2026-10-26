import json
import sys
from pathlib import Path

ALERTS_DIR = Path(__file__).resolve().parents[1] / "alerts"

# These fictional records use familiar Wazuh fields and realistic, scenario-specific log sources.
# The label/title are benchmark metadata only; neither is included in the alert sent to the model.
# The first four records and the requested 8/4/5/3 distribution are preserved exactly.
# Fields per case: label, title, rule ID, level, description, source IP, user, location, service, log.
CASES = [
    ("TP", "Brute Force SSH Login", "5710", 10, "Multiple failed SSH login attempts", "192.168.1.45", "root", "/var/log/auth.log", "sshd", "Failed password for root from 192.168.1.45; repeated failures observed"),
    ("FP", "Scheduled Admin Backup", "100200", 7, "Many files accessed overnight", "192.168.1.10", "backup", "/var/log/backup.log", "backup-agent", "scheduled admin backup read approved files at 02:00"),
    ("TN", "Normal User Login", "5500", 2, "Successful routine login", "192.168.1.21", "operator", "/var/log/auth.log", "sshd", "Accepted publickey for operator from 192.168.1.21"),
    ("FN", "Low-and-Slow Port Scan", "100102", 2, "Low-rate connections to several ports", "192.168.1.65", "unknown", "/var/log/syslog", "firewall", "TCP SYN from 192.168.1.65 to ports 22, 80, 443, one connection per minute"),
    ("TP", "Privilege Escalation", "5501", 12, "Unauthorized privilege escalation attempt", "192.168.1.20", "svc-web", "/var/log/auth.log", "sudo", "svc-web attempted sudo execution of /tmp/unauthorized-root-shell without approval"),
    ("TP", "Suspicious Process Execution", "100100", 9, "Suspicious shell command execution", "192.168.1.33", "analyst", "/var/log/audit/audit.log", "auditd", "EXECVE bash -c with encoded command launching an unapproved script"),
    ("FP", "Authorized Vulnerability Scan", "100202", 5, "Port sweep pattern detected", "192.168.1.13", "scanner", "/var/log/syslog", "scanner", "approved vulnerability scanner ran scheduled inventory against authorized subnet"),
    ("TN", "Scheduled Health Check", "100203", 1, "Routine service activity", "192.168.1.22", "service", "/var/log/syslog", "systemd", "scheduled health check completed successfully"),
    ("TP", "Unauthorized File Access", "100101", 11, "Sensitive file read by unexpected process", "192.168.1.52", "www-data", "/var/log/audit/audit.log", "auditd", "www-data process read /etc/shadow; access denied by file policy"),
    ("FN", "Low-and-Slow SSH Brute Force", "5710", 3, "Single authentication failure", "192.168.1.61", "admin", "/var/log/auth.log", "sshd", "Failed password for admin from 192.168.1.61; one attempt in this interval, similar attempts were spaced out"),
    ("TN", "Routine Project File Access", "100204", 1, "Normal file access", "192.168.1.23", "user4", "/var/log/audit/audit.log", "auditd", "user4 read own project documentation in authorized directory"),
    ("TP", "Malware Detection", "100103", 13, "Malicious attachment execution detected", "192.168.1.88", "user1", "/var/log/clamav/clamd.log", "clamd", "user1 opened and executed malicious email attachment; malware signature detected and file quarantined"),
    ("FP", "Approved Admin Package Update", "100201", 8, "Administrative command flagged", "192.168.1.12", "admin", "/var/log/auth.log", "sudo", "admin ran approved apt-get update during the authorized maintenance window"),
    ("TP", "Rapid Port Scan", "100102", 10, "Rapid connection attempts to many ports", "192.168.1.77", "unknown", "/var/log/syslog", "firewall", "rapid TCP connection attempts from 192.168.1.77 to ports 21, 22, 23, 80, 443, 445"),
    ("TN", "Monitoring Agent Connection", "100205", 2, "Expected outbound connection", "192.168.1.24", "monitor", "/var/log/syslog", "monitor-agent", "approved monitoring agent sent its scheduled heartbeat to manager"),
    ("FN", "Stealthy Sensitive File Access", "100101", 2, "Low-volume file access anomaly", "192.168.1.64", "svc-app", "/var/log/audit/audit.log", "auditd", "svc-app read a small amount of sensitive payroll records outside its usual access pattern"),
    ("TP", "Malicious PowerShell Execution", "100100", 9, "Suspicious script interpreter activity", "192.168.1.34", "analyst", "/var/log/audit/audit.log", "auditd", "EXECVE powershell launched an unapproved encoded script from a temporary directory"),
    ("FP", "Mistyped SSH Password", "5710", 6, "Several SSH authentication failures", "192.168.1.11", "deploy", "/var/log/auth.log", "sshd", "deploy user had several failed password attempts, then authenticated successfully during approved maintenance"),
    ("TN", "Successful Service Login", "5500", 2, "Successful routine service login", "192.168.1.25", "service", "/var/log/auth.log", "sshd", "Accepted publickey for service from approved internal address"),
    ("TP", "Credential Brute Force", "5710", 10, "Repeated failed account logins", "192.168.1.90", "admin", "/var/log/auth.log", "sshd", "repeated failed passwords against multiple accounts from 192.168.1.90"),
]


def main() -> None:
    # The requested arrow must print correctly under Windows PowerShell code pages.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    for index, (label, title, rule_id, level, desc, srcip, user, location, service, log) in enumerate(CASES, 1):
        host = f"web-server-{(index % 3) + 1:02d}"
        alert = {
            "id": f"synthetic-alert-{index:03d}",
            "timestamp": f"2024-06-{(index % 28) + 1:02d}T{index % 24:02d}:{(index * 3) % 60:02d}:11",
            "rule": {"id": rule_id, "level": level, "description": desc},
            "agent": {"id": f"{(index % 9) + 1:03d}", "name": host},
            "manager": {"name": "wazuh-manager"},
            "location": location,
            "data": {"srcip": srcip, "dstuser": user},
            "full_log": f"Jun {index:02d} 10:23:11 {host} {service}[1234]: {log}",
            "alert_type": label,
        }
        (ALERTS_DIR / f"alert_{index:03d}.json").write_text(json.dumps(alert, indent=2) + "\n", encoding="utf-8")
        print(f"Generated alert_{index:03d}.json → {label} | {title}", flush=True)
    print(f"Done. Generated {len(CASES)} alerts in alerts/", flush=True)


if __name__ == "__main__":
    main()
