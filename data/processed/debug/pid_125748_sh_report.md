```markdown
# Incident Report

## Summary
Anomalous process activity was detected involving the `sh` shell process (PID: 125748) and the `/usr/bin/curl` utility. The activity is characterized by a high anomaly score (298.974) and shows a pattern of repeated execution of `curl` from within a shell, with evidence of data exchange via a file descriptor. This pattern matches several recent similar cases.

**Verdict: Malicious**

## Evidence
*   **Primary Process:** The target process is `sh` with PID 125748.
*   **Key Activity:** The `sh` process executed `/usr/bin/curl` multiple times.
*   **Data Flow:** Evidence shows a cyclic read/write pattern between the `sh` process and a file descriptor (`fd:3_pid:124637`), indicating potential command input or output exfiltration.
*   **Anomaly Score:** The associated path activity has a consistently high anomaly score of 298.974 across all measured supports.
*   **Historical Context:** Three similar prior cases were identified (e.g., case_1773575334_cbee1adc), all involving `sh` executing `curl` with identical high anomaly scores, suggesting a recurring pattern or campaign.

## ATT&CK Mapping
| Stage | Technique | Confidence | Evidence |
| :--- | :--- | :--- | :--- |
| Execution | Command and Scripting Interpreter: Unix Shell | High | `sh` process is the primary actor. |
| Execution | Command and Scripting Interpreter: Unix Shell | Medium | `sh -[EX x1]-> /usr/bin/curl` |
| Exfiltration | Exfiltration Over C2 Channel | Low | Repeated execution of `/usr/bin/curl` suggests potential data transfer. The data flow to/from `fd:3_pid:124637` may be part of this process. |

## Impact
*   **Potential Data Exposure:** The use of `curl` initiated from a shell, especially with associated data flow, poses a high risk for unauthorized data exfiltration.
*   **System Compromise:** The activity indicates an attacker has established a foothold with execution capabilities.
*   **Lateral Movement Potential:** This could be a precursor stage for downloading additional tools or establishing persistence.

## Recommended Actions
1.  **Containment:** Immediately isolate the affected host (where PID 125748 is running) from the network to prevent further data exfiltration or command & control (C2) communication.
2.  **Investigation:**
    *   Capture a full memory dump of the host for forensic analysis.
    *   Examine the command-line arguments of the `sh` (PID: 125748) and any `curl` processes to determine the target URLs and any data involved.
    *   Inspect the file descriptor `fd:3_pid:124637` (if still open) and related files or pipes to understand the data being transferred.
    *   Review logs (auth, cron, bash history) to identify the initial access vector.
3.  **Eradication:** Terminate the malicious `sh` process tree. Search for and remove any associated artifacts, such as downloaded files or scripts.
4.  **Hunting:** Search all systems in the environment for similar patterns of `sh` spawning `curl` with high anomaly scores, referencing the provided similar case IDs.

## Confidence
**High.** The verdict is based on:
*   A consistently high, statistically rare anomaly score.
*   A clear pattern of execution matching known malicious cases.
*   Evidence of data flow consistent with exfiltration or C2 activity.
*   The inherent risk of `curl` being invoked from an unexpected shell context.
```

## Unverified Mentions
{
  "paths": [
    "/from",
    "/write"
  ],
  "ips": [],
  "techniques": []
}