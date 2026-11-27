"""Offline threat signature database for ProcMon CSV log analysis (Ring 3 & Ring 0)."""

KNOWN_MALWARE_PROCESSES = {
    "mimikatz.exe",
    "psexec.exe",
    "meterpreter.exe",
    "nc.exe",
    "ncat.exe",
    "netcat.exe",
    "cobaltstrike.exe",
    "procdump.exe",
    "hack.exe",
    "unknown_inject.exe",
    "injector.exe",
}

# Each rule: id, ring, severity, threat_type, title, why, action, matcher(row)
# Ordered from highest specificity / severity downward.
THREAT_RULES = [
    # --- Ring 0 (Kernel Mode) Threat Indicators ---
    {
        "id": "R0_KERNEL_EXPLOIT_PHYSMEM",
        "ring": "Ring 0 (Kernel Mode)",
        "severity": "Critical",
        "threat_type": "Kernel Exploit",
        "title": "Direct Physical Memory Access",
        "why": (
            "Accessing \\Device\\PhysicalMemory bypasses OS virtual memory isolation, "
            "allowing attackers to read or patch kernel structures directly."
        ),
        "action": "Isolate the endpoint immediately and inspect active kernel drivers.",
        "op_contains": ["IRP_MJ_CREATE", "CreateFile"],
        "path_contains": ["\\device\\physicalmemory"],
    },
    {
        "id": "R0_DRIVER_LOAD",
        "ring": "Ring 0 (Kernel Mode)",
        "severity": "Critical",
        "threat_type": "Driver Load",
        "title": "Kernel Driver Load Attempt",
        "why": (
            "Loading a kernel-mode driver grants Ring 0 execution privileges, enabling "
            "rootkit installation and security control bypass."
        ),
        "action": "Verify driver digital signature and block unsigned or unknown .sys files.",
        "op_equals": ["NtLoadDriver", "ZwLoadDriver", "Load Image"],
        "path_contains": [".sys"],
    },
    {
        "id": "R0_ROOTKIT_INSTALL",
        "ring": "Ring 0 (Kernel Mode)",
        "severity": "Critical",
        "threat_type": "Rootkit Install",
        "title": "Kernel Service Driver Registration",
        "why": (
            "Modifying Services\\*\\ImagePath registers a Windows service or kernel driver "
            "to load automatically with SYSTEM/kernel privileges."
        ),
        "action": "Inspect the target registry key and remove unauthorized service entries.",
        "op_contains": ["RegSetValue", "RegSetInfoKey"],
        "path_contains": ["services\\", "imagepath"],
        "path_match_all": True,
    },
    {
        "id": "R0_ROOTKIT_DROP",
        "ring": "Ring 0 (Kernel Mode)",
        "severity": "Critical",
        "threat_type": "Rootkit Drop",
        "title": "Driver File Drop in System32\\drivers",
        "why": (
            "Writing files into System32\\drivers\\ is a classic rootkit staging step "
            "to persist malicious kernel drivers."
        ),
        "action": "Quarantine the dropped file and check file hash against threat intelligence.",
        "op_contains": ["WriteFile", "CreateFile"],
        "path_contains": ["system32\\drivers\\"],
    },
    {
        "id": "R0_DRIVER_ABUSE",
        "ring": "Ring 0 (Kernel Mode)",
        "severity": "High",
        "threat_type": "Driver Abuse",
        "title": "Custom Driver IOCTL Communication",
        "why": (
            "DeviceIoControl calls to non-standard drivers can exploit Bring Your Own "
            "Vulnerable Driver (BYOVD) flaws to disable EDR/antivirus."
        ),
        "action": "Audit the target device handle and verify the owning driver.",
        "op_contains": ["DeviceIoControl"],
        "path_contains": ["\\device\\"],
    },
    # --- Ring 3 (User Mode) Threat Indicators ---
    {
        "id": "R3_WRITE_PROCESS_MEMORY",
        "ring": "Ring 3 (User Mode)",
        "severity": "Critical",
        "threat_type": "Process Injection",
        "title": "WriteProcessMemory Cross-Process Injection",
        "why": (
            "Cross-process memory write operations are a primary indicator of process "
            "injection. An external process modified the virtual address space of another "
            "running process to alter runtime state or inject code."
        ),
        "action": "Terminate the source process and inspect the target process memory integrity.",
        "op_contains": ["WriteProcessMemory"],
    },
    {
        "id": "R3_CREATE_REMOTE_THREAD",
        "ring": "Ring 3 (User Mode)",
        "severity": "Critical",
        "threat_type": "DLL Injection",
        "title": "CreateRemoteThread Execution",
        "why": (
            "Spawning a thread inside another process's address space is commonly used "
            "for DLL injection and shellcode execution."
        ),
        "action": "Terminate the injecting process and audit loaded modules in the target.",
        "op_contains": ["CreateRemoteThread"],
    },
    {
        "id": "R3_VIRTUAL_ALLOC_EX",
        "ring": "Ring 3 (User Mode)",
        "severity": "Critical",
        "threat_type": "Shellcode Staging",
        "title": "VirtualAllocEx Remote Memory Allocation",
        "why": (
            "Allocating executable memory inside a remote process is a precursor to "
            "writing and executing injected payloads."
        ),
        "action": "Correlate with WriteProcessMemory or CreateRemoteThread events and terminate.",
        "op_contains": ["VirtualAllocEx"],
    },
    {
        "id": "R3_APC_INJECTION",
        "ring": "Ring 3 (User Mode)",
        "severity": "Critical",
        "threat_type": "APC Injection",
        "title": "NtQueueApcThread Queueing",
        "why": (
            "Queueing an Asynchronous Procedure Call (APC) to another process's thread "
            "forces it to execute attacker-controlled code."
        ),
        "action": "Terminate the source process and inspect suspended/alertable threads.",
        "op_contains": ["NtQueueApcThread", "QueueUserAPC"],
    },
    {
        "id": "R3_READ_PROCESS_MEMORY",
        "ring": "Ring 3 (User Mode)",
        "severity": "High",
        "threat_type": "Memory Scraping",
        "title": "ReadProcessMemory Cross-Process Read",
        "why": (
            "Reading memory from another process can harvest credentials, session tokens, "
            "or sensitive runtime state."
        ),
        "action": "Verify whether the caller is an authorized debugger or security monitor.",
        "op_contains": ["ReadProcessMemory"],
    },
    {
        "id": "R3_OPEN_PROCESS_PRIV",
        "ring": "Ring 3 (User Mode)",
        "severity": "High",
        "threat_type": "Privilege Acquisition",
        "title": "OpenProcess with Memory Write/All Access",
        "why": (
            "Requesting PROCESS_VM_WRITE or PROCESS_ALL_ACCESS on another process grants "
            "full handle rights needed for memory tampering."
        ),
        "action": "Block untrusted processes from acquiring high-privilege process handles.",
        "op_contains": ["OpenProcess"],
        "detail_contains": ["process_vm_write", "process_all_access"],
    },
    {
        "id": "R3_KEYLOGGER_HOOK",
        "ring": "Ring 3 (User Mode)",
        "severity": "High",
        "threat_type": "Keylogger / Hook",
        "title": "Global Windows Hook Installation",
        "why": (
            "SetWindowsHookEx can intercept keyboard strokes and UI messages globally "
            "across applications for credential theft."
        ),
        "action": "Identify the hooking DLL/executable and revoke persistence.",
        "op_contains": ["SetWindowsHookEx"],
    },
    {
        "id": "R3_PERSISTENCE_RUN_KEY",
        "ring": "Ring 3 (User Mode)",
        "severity": "High",
        "threat_type": "Persistence",
        "title": "Registry Run / RunOnce Persistence",
        "why": (
            "Writing to CurrentVersion\\Run or RunOnce ensures a binary executes "
            "automatically on every user logon."
        ),
        "action": "Review the added startup value and remove unauthorized entries.",
        "op_contains": ["RegSetValue", "RegSetInfoKey"],
        "path_contains": ["\\currentversion\\run", "\\currentversion\\runonce"],
    },
    {
        "id": "R3_KNOWN_MALWARE_PROCESS",
        "ring": "Ring 3 (User Mode)",
        "severity": "Critical",
        "threat_type": "Known Threat Binary",
        "title": "Known Attack / Tamper Tool Execution",
        "why": (
            "A process matching a known offensive, credential-dumping, or memory-tampering "
            "tool name was observed executing on the host."
        ),
        "action": "Quarantine the executable immediately and review its child/target processes.",
        "process_in": KNOWN_MALWARE_PROCESSES,
        "op_equals": ["Process Start", "Process Create", "Thread Create"],
    },
    {
        "id": "R3_KNOWN_MALWARE_FILE_MAP",
        "ring": "Ring 3 (User Mode)",
        "severity": "High",
        "threat_type": "Memory Mapping / Payload Load",
        "title": "Suspicious Process File Mapping or Image Load",
        "why": (
            "A flagged process mapped an executable or DLL into virtual memory, which "
            "often precedes state injection or API hooking."
        ),
        "action": "Inspect the mapped path and verify binary provenance.",
        "process_in": KNOWN_MALWARE_PROCESSES,
        "op_equals": ["CreateFileMapping", "Load Image"],
    },
    {
        "id": "R3_PROCESS_PROFILING",
        "ring": "Ring 3 (User Mode)",
        "severity": "Medium",
        "threat_type": "Process Profiling",
        "title": "Active Process Profiling Activity",
        "why": (
            "Process Profiling events indicate continuous inspection of thread/memory "
            "activity, either by a security monitor or an attacker enumerating targets."
        ),
        "action": "Confirm whether the profiling process is an authorized watchdog.",
        "op_equals": ["Process Profiling"],
    },
    {
        "id": "R3_AUDIT_LOG_WRITE",
        "ring": "Ring 3 (User Mode)",
        "severity": "Low",
        "threat_type": "Audit / Telemetry Write",
        "title": "Security Audit Log Modification",
        "why": (
            "A process wrote to a security audit log file. Expected for watchdogs, "
            "but suspicious if performed by an untrusted binary."
        ),
        "action": "Verify that only the authorized monitor writes to audit logs.",
        "op_equals": ["WriteFile"],
        "path_contains": ["security_audit_log"],
    },
]
