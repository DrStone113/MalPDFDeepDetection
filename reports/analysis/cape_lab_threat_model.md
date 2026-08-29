# CAPEv2 Laboratory Threat Model

This thesis-scale threat model covers a future isolated laboratory only. The current milestone is documentation/configuration validation and has no live sandbox, guest, sample, or network activity.

| Threat | Impact | Mitigation | Residual risk |
| --- | --- | --- | --- |
| Malicious guest activity | guest compromise and untrusted artifacts | dedicated host, isolated guest network, one clean snapshot per sample, no host shares | hypervisor/guest escape is not eliminated. |
| Network escape or accidental trusted-LAN exposure | spread, reconnaissance, or harm to personal/university systems | no bridged LAN, deny trusted destinations, separate management/analysis networks, offline default | firewall/routing misconfiguration or human error. |
| Contaminated shared storage | trusted systems receive executables or data | prohibit shares/clipboard/drive mapping; JSON-only egress; isolated artifact storage | manual transfer mistakes. |
| Credential exposure | account compromise | no personal accounts, secrets, SSH keys, sync clients, or cloud storage in host/guest | administrative error during future setup. |
| Failed snapshot revert | cross-sample contamination and invalid evidence | verify revert before use; record snapshot/config version; stop on failure | hypervisor/storage failure. |
| Sandbox-host compromise | loss of containment and data integrity | dedicated host, minimal privileges, firewall, restricted management access, configuration backups | a sandbox host remains higher-risk than a normal workstation. |
| Malicious report content | parser compromise or accidental payload handling | parser treats JSON as data; compact normalized output; no report execution or web rendering | parser defects and oversized/malformed input require limits in a future review. |
| Artifact mishandling | raw binaries or sensitive data enter Git/trusted storage | checksum/provenance, explicit egress, Git ignores, isolated retention policy | unauthorized manual copying. |
| Human error / unsafe workflow | any of the above | formal checklist, two-person/reviewer approval gate, one sample at a time, incident stop rule | residual operational mistakes. |

If any containment control fails, there is no malware execution. The response is to stop, isolate as appropriate, preserve logs, and review the boundary before any future work resumes.
