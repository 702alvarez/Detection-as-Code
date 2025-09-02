# PowerShell EncodedCommand Detection
- **Technique**: T1059.001 – PowerShell
- **Rule**: Detects use of -EncodedCommand in PowerShell command lines.
- **Triage**:
  1. Review incident in Sentinel.
  2. Check initiating process tree in MDE.
  3. Correlate with user activity.
- **Containment**:
  - Isolate device in MDE if malicious.
  - Disable user in Entra ID if compromised.