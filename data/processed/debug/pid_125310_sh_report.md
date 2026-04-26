```markdown
# Incident Report

**Target Process:** `sh` (pid=125310)
**Report Time:** Analysis based on provided provenance data.
**Verdict:** **Malicious**

## Summary
Anomalous activity was detected involving the Bourne shell (`sh`) process with PID 125310. The process exhibits a rare and repetitive pattern of writing to its own file descriptors (`fd:3`, `fd:4`). This behavior is highly consistent with three other recent, high-scoring incidents involving `sh` processes, strongly suggesting a coordinated or scripted malicious execution.

## Evidence
The primary evidence is derived from system call provenance analysis.

*   **Primary IOC:** The process `sh` (pid=125310) is the subject of the alert.
*   **Anomalous Behavior:** The `sh` process performed multiple, rapid write (`WR`) operations to its own file descriptors `fd:3_pid:125310` and `fd:4_pid:125310`. This forms a self-referential loop in the provenance graph (`sh -> fd -> sh`).
*   **Statistical Rarity:** The observed provenance paths have exceptionally high anomaly scores (ranging from 119.589 to 298.974), indicating this behavior pattern is statistically rare in the observed environment.
*   **Correlation with Similar Cases:** Three previous cases with identical high scores (`298.974`) involved `sh` processes (pids: 124953, 125116, 124643) executing `curl` commands. While the exact command for pid 125310 is not shown, the identical behavioral fingerprint (high score, `sh` process, rare write patterns) strongly links this incident to the previous malicious activity.

## ATT&CK Mapping
| Stage | Technique ID | Confidence | Evidence Snippet |
| :--- | :--- | :--- | :--- |
| Execution | Unknown | Medium | `sh -[WR x2]-> fd:3_pid:125310` |
| Execution | Unknown | Medium | `sh -[WR x2]-> fd:4_pid:125310` |

**Mapping Note:** The specific MITRE ATT&CK technique cannot be identified per the provided rules (`AllowedTechniques: None`). The activity maps to the **Execution** tactic, with the self-referential write pattern being indicative of script or command execution, potentially involving piping or redirection.

## Impact
*   **Potential Impact:** Unauthorized command execution, data exfiltration, or staging for further malicious actions. The correlation with previous `curl` executions suggests potential download or beaconing activity.
*   **Scope:** The activity is isolated to a single process and its descriptors, but its similarity to prior cases indicates a potential recurring threat.

## Recommended Actions
1.  **Containment:** Immediately isolate the host containing PID 125310 from the network to prevent potential command-and-control communication or data exfiltration.
2.  **Investigation:**
    *   Capture a full memory dump of the affected host for forensic analysis.
    *   Examine the command-line history and process tree to identify the parent of `sh` (pid=125310) and any child processes.
    *   Inspect the contents written to the file descriptors, if possible from audit logs or memory.
3.  **Eradication:** Terminate the `sh` process (pid=125310) and any related suspicious processes identified during investigation.
4.  **Hunting:** Search for other instances of `sh` processes with high `path_score` values or similar rare write patterns to file descriptors across the environment.
5.  **Review:** Audit system and user accounts for unauthorized access or privilege escalation that may have led to this execution.

## Confidence
**High**

The confidence is high due to:
*   The extremely high statistical anomaly scores associated with the behavior.
*   The precise correlation of this behavioral fingerprint (`sh` with high `path_score`) with three confirmed malicious cases involving `curl`.
*   The inherently suspicious nature of a shell process engaging in rapid, self-referential write operations, which is not typical for benign administrative or user tasks.
```