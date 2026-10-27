# Windows VMware metadata in doctor, 2026-10-21

The operator requested fewer manual console diagnostics after the approved
SSH endpoint refused connections. Read-only Windows VMware checks found one
running VM at `C:\VirtualMachine\Remnux.vmx`, VMware Tools state `running`,
and guest IP `192.168.217.10`. The selected VMX metadata says host-only
networking and disables clipboard copy/paste and drag-and-drop. These are
metadata observations, not complete runtime containment verification. A
runtime `ethernet0.connected` variable query returned no value, so its state
was not established by that query. No guest program was run.

Doctor now automatically adds a local `host_vmware` record only after an audit
transport failure. The fixed actions are inventory, Tools state and guest IP
for the identified VM. No guest credentials, shell, file operations, VMware
power/network actions or endpoint substitution are accepted. Output is
normalized to booleans, fixed reasons/Tools enums and a numeric IPv4 address;
raw errors and other VM paths are discarded. Each query has a three-second
timeout and rejects output above 4 KiB. Missing VMware/Tools or malformed
metadata leaves the observation unverified. Offline doctor does not query
either VMware or SSH, and successful audit calls do not use this fallback.

Live Windows `lab.ps1 doctor` at 2026-10-21T15:42:25Z returned:

```json
{
  "status": "not_ready",
  "reason": "lab_unreachable",
  "host_vmware": {
    "vm_running": true,
    "tools": "running",
    "guest_ipv4": "192.168.217.10",
    "expected_ipv4": "192.168.217.10",
    "address_matches": true,
    "reason": null
  }
}
```

This removes the need to ask the operator to retype the guest IP. It does
not reveal whether ssh.service is active, its listener settings, or whether
a firewall rejects connections. VMware Tools metadata is not used as an
alternate guest execution channel. Any privileged SSH repair remains an
operator action under AGENTS.md section 4. The helper does not start SSH or
change VM isolation, and no LAB test job or PDF processing ran.

Validation used Python 3.11.16 on Windows, dirty base commit
935fcee48797606d718aeace47b5fd91c2b95ce3. Eleven added mocked tests cover
metadata fallback, offline/audit precedence, the fixed guest/action selection,
stopped or missing guests/tools, malformed/oversized results, IP mismatch,
untrusted IP text and command timeout/argument restrictions. Full checks passed
147 tests, 0 failed/skipped, 306 AST files, content/diff checks, declared
dependency/import checks and pip consistency. Receipt:
`artifacts/tmp/maintenance/lab_workflow/windows_20261021T154129917452Z.json`.

Commands included the following, with the installed VMware vmrun executable:

```text
vmrun -T ws list
vmrun -T ws checkToolsState C:\VirtualMachine\Remnux.vmx
vmrun -T ws getGuestIPAddress C:\VirtualMachine\Remnux.vmx
vmrun -T ws readVariable C:\VirtualMachine\Remnux.vmx runtimeConfig ethernet0.connected
```

```powershell
.\.venv-windows-dev\Scripts\python.exe -B scripts/lab/check_local.py --save
.\lab.ps1 doctor
```

This Windows-only enhancement leaves the 14-file bootstrap identity
25302b72bad42984e97a8a0a3efe683f8c07424ccadaea005a6286e30457cfce
unchanged. Previous packages/reports and the user-owned AGENTS.md remain intact.
