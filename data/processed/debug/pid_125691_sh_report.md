# Incident Report

## Summary
An anomalous process chain involving the `sh` shell and the `/usr/bin/curl` utility was detected. The process `sh` with PID 125691 was identified as the target of investigation. Analysis of the provenance graph reveals a pattern where `sh` executes `/usr/bin/curl`, which then recursively executes itself multiple times. This activity is correlated with several similar historical cases showing identical behavioral patterns and high anomaly scores.

**Verdict: Malicious**

## Evidence
*   **Primary Process:** The target process is `sh` with PID 125691.
*   **Process Execution Chain:** The provenance graph shows `sh` executing `/usr/bin/curl`. Subsequently, `/usr/bin/curl` exhibits recursive self-execution (`/usr/bin/curl -[EX x1]-> /usr/bin/curl`) multiple times.
*   **Anomaly Score:** The associated rare paths have a consistently high anomaly score of 298.974.
*   **Historical Correlation:** Three similar prior cases (case_1773567398_659a8efd, case_1773564788_06ae0244, case_1773567297_8ef87fee) involving `sh` and `/usr/bin/curl` were identified, all with the same high score of 298.974, indicating a recurring pattern.
*   **IOC Context:** The Indicator of Compromise (IOC) `sh` is present in the allowed list and is central to the activity.

## ATT&CK Mapping
| Stage | Technique | Confidence | Evidence Snippet |
| :--- | :--- | :--- | :--- |
| Execution | Unknown | Medium | `sh -[EX x1]-> /usr/bin/curl` |
| Command and Control | Unknown | Medium | `/usr/bin/curl -[EX x1]-> /usr/bin/curl` (repeated) |

*Note: Specific MITRE ATT&CK Technique IDs could not be mapped as none were provided in the AllowedTechniques list.*

## Impact
The activity indicates a potential command execution and persistence mechanism. The recursive execution of `curl` is highly unusual for benign operations and suggests an attempt to download and execute additional payloads, establish a reverse shell, or perform beaconing for command and control (C2). The high anomaly score and correlation with previous similar incidents elevate the severity.

## Recommended Actions
1.  **Containment:** Immediately isolate the host(s) associated with PID 125691 and the linked PIDs (124637, 125001, 125007, 124840) from the network to prevent potential lateral movement or data exfiltration.
2.  **Investigation:**
    *   Capture a full memory dump of the affected system for forensic analysis.
    *   Examine the command-line arguments used in the `sh` and `/usr/bin/curl` processes (if available in logs or memory) to determine the target URL or payload.
    *   Review system and application logs for the timeframe of the activity to identify the initial access vector.
3.  **Eradication & Recovery:**
    *   Terminate the identified malicious processes (`sh` PID 125691 and related `curl` instances).
    *   Conduct a thorough malware scan on the affected system.
    *   If the system is deemed compromised, consider rebuilding it from a known-good backup or image after identifying the root cause.
4.  **Hunting:** Search for other instances of `sh` spawning `/usr/bin/curl` with recursive execution patterns across the environment.

## Confidence
**High.** The verdict is supported by:
*   A clear, anomalous provenance graph showing recursive execution.
*   A consistently high anomaly score (298.974) associated with the activity.
*   Strong correlation with multiple previous incidents exhibiting identical behavior (`sh` -> `curl`).
*   The presence of `sh` as a known IOC in the context of this alert.