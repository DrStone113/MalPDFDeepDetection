# CAPEv2 Laboratory Implementation Checklist

**Design-only checklist.** All boxes are intentionally unchecked. Completing a stage requires separate authorization; this file is not an installation or execution procedure.

## Stage A — Prepare dedicated Ubuntu host

- [ ] Confirm Host B is not the normal development workstation and contains no personal credentials or synced folders.
- [ ] Record hardware, Ubuntu 24.04 LTS baseline, storage plan, administrative access policy, and backup approach.
- [ ] Review firewall and separate management/analysis network design.

## Stage B — Install/configure KVM

- [ ] Review selected official CAPEv2 revision and hashes before installing any component.
- [ ] Confirm KVM/QEMU/libvirt design, access restrictions, and no guest bridge to trusted LAN.
- [ ] Record hypervisor/version provenance and snapshot capability.

## Stage C — Install pinned CAPEv2 revision

- [ ] Obtain written selection record for exact CAPEv2 commit and commit date.
- [ ] Review installer/configuration files; record hashes and retain sanitized configuration snapshot.
- [ ] Confirm only necessary routing components are privileged and normal services use the dedicated CAPE identity.

## Stage D — Create Windows guest

- [ ] Create the dedicated Windows 11 23H2 x64 analysis guest with local-only account.
- [ ] Record guest OS, PDF-application version, and all analysis-relevant software versions.
- [ ] Confirm no personal account, browser profile, trusted documents, or cloud sync is present.

## Stage E — Configure isolated networking

- [ ] Verify guest cannot reach trusted LAN, Host A, private services, router administration, or SMB shares.
- [ ] Verify offline default and management/analysis separation.
- [ ] Treat any controlled network-observation mode as a separate reviewed change; log its boundary tests.

## Stage F — Install CAPE agent

- [ ] Record the approved agent version and its operating requirements.
- [ ] Verify agent communication remains within the isolated analysis boundary.
- [ ] Complete harmless-only functional checks before a snapshot is created.

## Stage G — Create clean snapshot

- [ ] Record snapshot identifier, guest configuration version, and clean-state verification evidence.
- [ ] Demonstrate revert/destroy and clean restoration independently.

## Stage H — Validate using harmless samples

- [ ] Validate with harmless documents, then synthetic benign PDFs, under the offline mode.
- [ ] Confirm no trusted-network traffic, payload egress, or contaminated state.
- [ ] Retain only approved test metadata in controlled storage.

## Stage I — Verify report ingestion into MalPDFDeepDetection

- [ ] Export JSON report and required metadata only through a controlled channel.
- [ ] Record raw report SHA-256 and parse with `malpdf dynamic parse` without executing report content.
- [ ] Verify `dynamic-schema-v1`, adapter code SHA, feature availability semantics, and research-safe IDs.

## Stage J — Formal safety review before malware

- [ ] Complete every containment item in the lab design acceptance checklist.
- [ ] Obtain explicit written approval for authorised sample scope and network mode.
- [ ] Confirm one-sample-per-clean-state method, incident stop procedure, and artifact-retention plan.
- [ ] If any check fails, do not submit a malicious sample.
