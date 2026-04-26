```markdown
# Incident Report

## Summary
Anomalous process activity was detected involving the `sh` shell process (PID: 125116) and the `/usr/bin/curl` binary. The activity is characterized by a high anomaly score (298.974) and shows a pattern of the `sh` process executing `curl`, which then executes itself recursively multiple times. This pattern is consistent with several recent similar cases. The primary evidence is a rare provenance path linking these processes through file descriptor interactions.

**Verdict: Malicious**

## Evidence
*   **Primary Process:** `sh` (PID: 125116) is the target of investigation.
*   **Key Activity:** The `sh` process executed `/usr/bin/curl`.
*   **Anomalous Pattern:** `/usr/bin/curl` subsequently executed itself (`/usr/bin/curl -[EX x1]-> /usr/bin/curl`) multiple times in a recursive chain, as shown in the EvidenceGraph and RarePaths.
*   **Historical Correlation:** Three similar prior cases (case_1773567398_659a8efd, case_1773568272_86e4d965, case_1773563841_11cff8fc) show an identical pattern of `sh` executing `curl` with a matching high anomaly score (298.974).
*   **Provenance Context:** The rare path analysis reveals a complex interaction where `sh` writes to and reads from a file descriptor (`fd:3`) associated with PID 124637, which is part of the anomalous execution chain.
*   **Indicator of Compromise (IOC):** The process name `sh` is listed as an IOC.

## ATT&CK Mapping
| Stage | Technique ID | Technique Name | Confidence | Evidence Snippet |
| :--- | :--- | :--- | :--- | :--- |
| Execution | N/A | Command and Scripting Interpreter | High | `sh -[EX x1]-> /usr/bin/curl` |
| Command and Control | N/A | Application Layer Protocol | Medium | Repeated, recursive execution of `/usr/bin/curl` suggests potential use for C2 communication or data exfiltration. |

*(Note: Specific MITRE ATT&CK Technique IDs are not provided in the AllowedTechniques list and therefore cannot be referenced.)*

## Impact
*   **Potential Data Exfiltration:** The recursive use of `curl` is highly indicative of an attempt to communicate with an external command and control (C2) server or exfiltrate data.
*   **Persistence & Lateral Movement:** The shell (`sh`) activity could be a precursor to downloading additional payloads or establishing a persistent foothold.
*   **System Integrity:** The anomalous, scored behavior suggests a deviation from normal system operation, posing a risk to system integrity and confidentiality.

## Recommended Actions
1.  **Containment:** Immediately isolate the affected host from the network to prevent potential C2 communication or data exfiltration.
2.  **Investigation:**
    *   Capture a full memory dump of the host for forensic analysis.
    *   Examine the command-line arguments for the `sh` (PID: 125116) and `curl` processes, if available in logs.
    *   Review network connections established by PID 125116 and any child `curl` processes.
    *   Search for dropped files or scripts related to this activity chain.
3.  **Eradication:** Terminate the `sh` process (PID: 125116) and all related child processes (e.g., the recursive `curl` instances).
4.  **Recovery & Hardening:**
    *   Restore the host from a known-good backup or re-image it after investigation.
    *   Review and audit cron jobs, systemd services, and user profiles for unauthorized entries that may have spawned the `sh` process.
    *   Consider implementing application allowlisting to restrict the execution of `curl` and other tools to specific, authorized users and contexts.

## Confidence
**High.** The verdict is based on:
*   A consistently high anomaly score (298.974) across the current and three historical, identical cases.
*   The presence of `sh` as a named IOC.
*   The clearly anomalous behavioral pattern of a recursive `curl` execution chain spawned from a shell, which is a strong indicator of malicious command-and-control activity.
```