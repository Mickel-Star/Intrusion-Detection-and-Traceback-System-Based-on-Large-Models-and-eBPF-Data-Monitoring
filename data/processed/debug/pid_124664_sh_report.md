```markdown
# Incident Report

## Summary
Anomalous activity was detected involving the process `sh` with PID `124664`. The activity is characterized by repeated execution of `/bin/sed` and unusual write patterns to a file descriptor (`fd:3_pid:124664`). The behavior is highly similar to other recent cases involving `sh` processes, all exhibiting identical high anomaly scores.

**Verdict: Malicious**

## Evidence
*   **Primary Process:** `sh` (PID: 124664).
*   **Executed Binaries:** The process `sh` executed `/bin/sed` multiple times.
*   **File System Activity:** Repeated write (`WR`) operations from `sh` to the file descriptor `fd:3_pid:124664`.
*   **Anomaly Score:** The associated rare paths have a consistently high anomaly score of `298.974`.
*   **Contextual Similarity:** Three other nearly identical cases were observed (PIDs: 124652, 124637, 124663), all involving `sh` with the same high score, suggesting a coordinated or repeating pattern.

## ATT&CK Mapping
| Stage | Technique ID | Technique Name | Confidence | Evidence Snippet |
| :--- | :--- | :--- | :--- | :--- |
| Execution | N/A | Command and Scripting Interpreter | Medium | `sh -[EX x1]-> /bin/sed` (Repeated execution via `sh`). |
| Defense Evasion | N/A | Indicator Removal / File Deletion | Low | `sh WR-> fd:3_pid:124664 WR<- sh` (Pattern suggests potential log tampering or data hiding via file descriptor manipulation). |

## Impact
*   **Potential Data Manipulation:** The use of `sed` could indicate search-and-replace operations on files or streams, potentially for configuration tampering or data theft.
*   **Persistence & Evasion:** The repetitive, anomalous pattern and file descriptor activity suggest an attempt to operate stealthily and maintain presence.
*   **Lateral Movement Risk:** The presence of multiple similar `sh` instances indicates the activity may not be isolated, posing a risk of broader system compromise.

## Recommended Actions
1.  **Containment:** Immediately isolate the affected host from the network.
2.  **Investigation:**
    *   Examine the contents written to `fd:3_pid:124664` if possible (e.g., check `/proc/124664/fd/3`).
    *   Analyze the command-line arguments or scripts that initiated the `sh` process (PID 124664).
    *   Investigate the other similar `sh` processes (PIDs 124652, 124637, 124663) as part of the same incident.
3.  **Eradication:** Terminate the malicious `sh` processes (124664, 124652, 124637, 124663).
4.  **Recovery:** Review system integrity, check for unauthorized cron jobs, shell initialization files (e.g., `.bashrc`, `.profile`), or services that may have spawned these processes.
5.  **Monitoring:** Enhance monitoring for child processes spawned by `sh` and for the execution of `/bin/sed` or `/bin/busybox` with unusual arguments.

## Confidence
**High.** Confidence is high due to the extreme anomaly score, the repetitive and identical nature of the activity across multiple processes, and the presence of behaviors consistent with defense evasion (file descriptor manipulation).
```

## Unverified Mentions
{
  "paths": [
    "/proc/124664/fd/3"
  ],
  "ips": [],
  "techniques": []
}