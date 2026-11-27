"""
ThreatLens — Offline Threat Pattern Database
=============================================
Comprehensive rule-based detection for ProcMon CSV log analysis.
Covers Ring 0 (Kernel) and Ring 3 (User-Mode) threat indicators.

Each rule is a dict with:
  - category:    Ring level / threat family
  - operation:   ProcMon "Operation" column match (substring, case-insensitive)
  - path_pattern: Optional regex on "Path" column (registry keys, file paths, devices)
  - process_pattern: Optional regex on "Process Name" column
  - detail_pattern: Optional regex on "Detail" column
  - severity:    "critical" | "high" | "medium" | "low"
  - threat_type: Human-readable threat label
  - description: Plain-English explanation of why this is dangerous
  - mitre_id:    MITRE ATT&CK technique ID (for credibility in pitch)
"""

import re

# ═══════════════════════════════════════════════════════════════
#  KNOWN MALICIOUS / SUSPICIOUS PROCESS NAMES
# ═══════════════════════════════════════════════════════════════
KNOWN_MALICIOUS_PROCESSES = {
    # Offensive security tools
    "mimikatz.exe":      ("critical", "Credential Dumping Tool", "Mimikatz extracts plaintext passwords, hashes, and Kerberos tickets from Windows memory — a primary post-exploitation credential theft tool."),
    "meterpreter":       ("critical", "Metasploit Payload",     "Meterpreter is a Metasploit attack payload that provides remote shell access, file manipulation, and privilege escalation on compromised systems."),
    "psexec.exe":        ("high",     "Remote Execution Tool",  "PsExec enables remote command execution across networked Windows machines — commonly abused for lateral movement in attacks."),
    "psexec64.exe":      ("high",     "Remote Execution Tool",  "64-bit variant of PsExec for remote process execution and lateral movement."),
    "cobalt":            ("critical", "Cobalt Strike Beacon",   "Cobalt Strike is a commercial adversary simulation tool frequently used in real-world attacks for C2 communication and post-exploitation."),
    "beacon.exe":        ("critical", "C2 Beacon",              "Likely a command-and-control beacon process communicating with an attacker's infrastructure."),
    "nc.exe":            ("high",     "Netcat Reverse Shell",   "Netcat can establish reverse shells, transfer files, and create network backdoors — a Swiss Army knife for attackers."),
    "ncat.exe":          ("high",     "Ncat Reverse Shell",     "Nmap's Ncat utility — used for network connections, often for reverse shells or data exfiltration."),
    "powershell_ise.exe":("medium",   "PowerShell ISE",         "PowerShell ISE can be used to run obfuscated attack scripts — monitor for encoded command execution."),
    "certutil.exe":      ("medium",   "LOLBin File Download",   "Certutil is a legitimate Windows tool frequently abused to download malicious payloads from the internet (Living-off-the-Land)."),
    "bitsadmin.exe":     ("medium",   "LOLBin File Download",   "BITSAdmin is a legitimate Windows tool abused to download files stealthily in the background."),
    "mshta.exe":         ("high",     "Script Execution via HTA","MSHTA executes HTML Applications — frequently abused to run VBScript/JScript payloads bypassing application whitelisting."),
    "regsvr32.exe":      ("medium",   "LOLBin DLL Execution",   "Regsvr32 can load and execute arbitrary DLLs/scripts — commonly used to bypass AppLocker restrictions."),
    "rundll32.exe":      ("medium",   "LOLBin DLL Execution",   "Rundll32 executes DLL functions — frequently abused to run malicious code through legitimate Windows binaries."),
    "wmic.exe":          ("medium",   "WMI Execution",          "WMIC can execute processes, query system info, and perform lateral movement via Windows Management Instrumentation."),
    "cscript.exe":       ("medium",   "Script Host Execution",  "Windows Script Host executing VBScript/JScript — often used to run malicious scripts downloaded by attackers."),
    "wscript.exe":       ("medium",   "Script Host Execution",  "Windows Script Host — GUI-based script execution often used for malware droppers."),
    "hack.exe":          ("critical", "Known Project Injector",  "This matches the project's own state-injection simulator — demonstrates detection of WriteProcessMemory-based attacks."),
}

# ═══════════════════════════════════════════════════════════════
#  RING 3 (USER MODE) THREAT RULES
# ═══════════════════════════════════════════════════════════════
RING3_RULES = [
    # --- Process Injection Family ---
    {
        "category": "Ring 3 — Process Injection",
        "operation": "WriteProcessMemory",
        "severity": "critical",
        "threat_type": "Cross-Process Memory Injection",
        "description": "An external process wrote directly into another process's virtual memory space. This is the primary mechanism for process injection attacks — injecting malicious code or modifying runtime state variables to hijack application behavior.",
        "mitre_id": "T1055.001"
    },
    {
        "category": "Ring 3 — Process Injection",
        "operation": "CreateRemoteThread",
        "severity": "critical",
        "threat_type": "Remote Thread Injection (DLL Injection)",
        "description": "A process created a thread inside another process's address space. This is the classic DLL injection technique — the remote thread typically calls LoadLibrary to load a malicious DLL into the victim process.",
        "mitre_id": "T1055.001"
    },
    {
        "category": "Ring 3 — Process Injection",
        "operation": "VirtualAllocEx",
        "severity": "critical",
        "threat_type": "Remote Memory Allocation (Shellcode Staging)",
        "description": "Memory was allocated inside another process's address space with execute permissions. This is typically the first step of shellcode injection — allocating a writable+executable buffer in the target before writing exploit code.",
        "mitre_id": "T1055.001"
    },
    {
        "category": "Ring 3 — Process Injection",
        "operation": "NtQueueApcThread",
        "severity": "critical",
        "threat_type": "APC Injection",
        "description": "An Asynchronous Procedure Call was queued to a thread in another process. APC injection forces a target thread to execute attacker-controlled code when it enters an alertable wait state.",
        "mitre_id": "T1055.004"
    },
    {
        "category": "Ring 3 — Process Injection",
        "operation": "NtMapViewOfSection",
        "severity": "high",
        "threat_type": "Section Mapping Injection",
        "description": "A shared memory section was mapped into another process's address space. This technique (Process Hollowing/Doppelgänging) allows an attacker to inject code without calling WriteProcessMemory.",
        "mitre_id": "T1055.012"
    },
    {
        "category": "Ring 3 — Process Injection",
        "operation": "SetThreadContext",
        "severity": "critical",
        "threat_type": "Thread Hijacking",
        "description": "A thread's execution context (instruction pointer, registers) was modified. This can redirect a legitimate thread to execute attacker-controlled code — a stealthier alternative to CreateRemoteThread.",
        "mitre_id": "T1055.003"
    },

    # --- Privilege & Handle Operations ---
    {
        "category": "Ring 3 — Privilege Escalation",
        "operation": "OpenProcess",
        "detail_pattern": r"(PROCESS_ALL_ACCESS|PROCESS_VM_WRITE|PROCESS_VM_OPERATION|0x1FFFFF|0x1F0FFF)",
        "severity": "high",
        "threat_type": "Privileged Process Handle Acquisition",
        "description": "A process opened a handle to another process with write/full-access permissions. This is a prerequisite for memory injection, process termination, or token theft — legitimate software rarely needs these elevated handle rights.",
        "mitre_id": "T1055"
    },
    {
        "category": "Ring 3 — Credential Access",
        "operation": "ReadProcessMemory",
        "detail_pattern": r"(lsass|winlogon|csrss)",
        "severity": "critical",
        "threat_type": "LSASS Memory Credential Dump",
        "description": "A process read memory from LSASS (Local Security Authority) or another credential-holding process. LSASS stores password hashes, Kerberos tickets, and plaintext credentials — reading its memory is the #1 technique for credential theft on Windows.",
        "mitre_id": "T1003.001"
    },
    {
        "category": "Ring 3 — Memory Scraping",
        "operation": "ReadProcessMemory",
        "severity": "medium",
        "threat_type": "Cross-Process Memory Read",
        "description": "A process read memory from another process. While debugging tools legitimately do this, unexpected cross-process reads may indicate memory scraping, credential harvesting, or surveillance of runtime state.",
        "mitre_id": "T1005"
    },

    # --- Hooking & Interception ---
    {
        "category": "Ring 3 — Input Capture",
        "operation": "SetWindowsHookEx",
        "severity": "high",
        "threat_type": "Global Hook Installation (Keylogger)",
        "description": "A global Windows hook was installed to intercept keyboard/mouse/message events system-wide. This is the classic keylogger technique — capturing every keystroke across all applications.",
        "mitre_id": "T1056.001"
    },
    {
        "category": "Ring 3 — API Hooking",
        "operation": "NtWriteVirtualMemory",
        "severity": "high",
        "threat_type": "Inline API Hooking",
        "description": "Direct memory write via native API — often used to patch (hook) API function prologues in-memory, redirecting legitimate system calls through attacker-controlled code for interception or evasion.",
        "mitre_id": "T1056"
    },

    # --- Persistence Mechanisms ---
    {
        "category": "Ring 3 — Persistence",
        "operation": "RegSetValue",
        "path_pattern": r"(HKLM|HKCU)\\(Software\\Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunServices)|SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\(Winlogon|Image File Execution))",
        "severity": "high",
        "threat_type": "Registry Autorun Persistence",
        "description": "A registry Run/RunOnce key was modified to execute a program at startup. This is the most common persistence mechanism — ensuring malware survives system reboots by auto-launching from the registry.",
        "mitre_id": "T1547.001"
    },
    {
        "category": "Ring 3 — Persistence",
        "operation": "RegSetValue",
        "path_pattern": r"\\Services\\.*\\(ImagePath|Start|Type)",
        "severity": "high",
        "threat_type": "Service Registration Persistence",
        "description": "A Windows service registry entry was created or modified. Attackers register malicious executables as services for persistence and to run with SYSTEM-level privileges.",
        "mitre_id": "T1543.003"
    },
    {
        "category": "Ring 3 — Persistence",
        "operation": "CreateFile",
        "path_pattern": r"\\(Startup|Start Menu\\Programs\\Startup)\\",
        "severity": "high",
        "threat_type": "Startup Folder Persistence",
        "description": "A file was created in the Windows Startup folder. Any executable or shortcut placed here runs automatically when the user logs in — a simple but effective persistence mechanism.",
        "mitre_id": "T1547.001"
    },
    {
        "category": "Ring 3 — Persistence",
        "operation": "RegSetValue",
        "path_pattern": r"\\(AppInit_DLLs|AppCertDLLs)",
        "severity": "critical",
        "threat_type": "AppInit DLL Injection Persistence",
        "description": "The AppInit_DLLs registry key was modified. DLLs listed here are loaded into every process that loads User32.dll — providing system-wide code injection persistence.",
        "mitre_id": "T1546.010"
    },

    # --- Defense Evasion ---
    {
        "category": "Ring 3 — Defense Evasion",
        "operation": "RegSetValue",
        "path_pattern": r"(DisableAntiSpyware|DisableAntiVirus|DisableRealtimeMonitoring|DisableBehaviorMonitoring|TamperProtection)",
        "severity": "critical",
        "threat_type": "Security Product Tampering",
        "description": "Windows Defender or antivirus settings were modified to disable protection. Attackers frequently disable security products as a first step before deploying malware payloads.",
        "mitre_id": "T1562.001"
    },
    {
        "category": "Ring 3 — Defense Evasion",
        "operation": "RegSetValue",
        "path_pattern": r"\\Policies\\Microsoft\\Windows Defender",
        "severity": "high",
        "threat_type": "Windows Defender Policy Modification",
        "description": "Group Policy settings for Windows Defender were modified — potentially to disable real-time protection, cloud-delivered protection, or automatic sample submission.",
        "mitre_id": "T1562.001"
    },

    # --- Suspicious File Operations ---
    {
        "category": "Ring 3 — Execution",
        "operation": "CreateFile",
        "path_pattern": r"\\(Temp|tmp|AppData\\Local\\Temp)\\.*\.(exe|dll|bat|ps1|vbs|js|hta|scr|cmd)",
        "severity": "medium",
        "threat_type": "Executable Written to Temp Directory",
        "description": "An executable or script file was created in a temporary directory. Malware frequently drops payloads in Temp folders because they are writable by any process without admin rights.",
        "mitre_id": "T1204"
    },
    {
        "category": "Ring 3 — Discovery",
        "operation": "RegQueryValue",
        "path_pattern": r"\\(Uninstall|InstalledComponents|SecurityProviders)",
        "severity": "low",
        "threat_type": "Installed Software Enumeration",
        "description": "Registry keys containing installed software information were queried. Attackers enumerate installed security products and applications to tailor their evasion and exploitation strategies.",
        "mitre_id": "T1518"
    },
]

# ═══════════════════════════════════════════════════════════════
#  RING 0 (KERNEL MODE) THREAT RULES
# ═══════════════════════════════════════════════════════════════
RING0_RULES = [
    {
        "category": "Ring 0 — Rootkit Installation",
        "operation": "RegSetValue",
        "path_pattern": r"\\Services\\[^\\]+\\ImagePath",
        "severity": "critical",
        "threat_type": "Kernel Driver Registration",
        "description": "A new kernel driver service was registered via the Services registry key. Malicious drivers operate at Ring 0 with full kernel-level access — able to hide processes, intercept I/O, and bypass all user-mode security controls. This is the hallmark of rootkit installation.",
        "mitre_id": "T1014"
    },
    {
        "category": "Ring 0 — Rootkit Installation",
        "operation": "CreateFile",
        "path_pattern": r"\\(System32|SysWOW64)\\drivers\\.*\.(sys|dll)",
        "severity": "critical",
        "threat_type": "Kernel Driver File Drop",
        "description": "A driver file (.sys) was written to the System32\\drivers directory. Legitimate driver installations go through Windows Update or signed installer packages — direct file drops here indicate rootkit deployment or unsigned driver loading.",
        "mitre_id": "T1014"
    },
    {
        "category": "Ring 0 — Kernel Exploit",
        "operation": "CreateFile",
        "path_pattern": r"\\Device\\PhysicalMemory",
        "severity": "critical",
        "threat_type": "Direct Physical Memory Access",
        "description": "A process attempted to open a handle to \\Device\\PhysicalMemory — the raw physical memory device object. This bypasses virtual memory isolation entirely, allowing direct read/write to any physical address. Used in kernel exploits and hardware-level rootkits.",
        "mitre_id": "T1068"
    },
    {
        "category": "Ring 0 — Driver Loading",
        "operation": "NtLoadDriver",
        "severity": "critical",
        "threat_type": "Runtime Kernel Driver Load",
        "description": "NtLoadDriver was called to load a kernel driver at runtime. Unless this is a known legitimate driver installation (GPU driver, printer driver), runtime driver loading is a strong indicator of rootkit or kernel exploit activity.",
        "mitre_id": "T1543.003"
    },
    {
        "category": "Ring 0 — Driver Loading",
        "operation": "ZwLoadDriver",
        "severity": "critical",
        "threat_type": "Runtime Kernel Driver Load (Native API)",
        "description": "ZwLoadDriver (kernel-mode native API) was called. This native syscall bypasses the standard service manager, making it harder to audit — a technique used by advanced rootkits.",
        "mitre_id": "T1543.003"
    },
    {
        "category": "Ring 0 — Driver Communication",
        "operation": "DeviceIoControl",
        "path_pattern": r"\\Device\\(?!Afd|HarddiskVolume|Mup|NamedPipe|LanmanRedirector|Tcp|Udp|Nsi|KsecDD|CNG)",
        "severity": "high",
        "threat_type": "Suspicious Driver IOCTL Communication",
        "description": "A DeviceIoControl call was sent to a non-standard kernel device driver. While legitimate drivers use IOCTLs, communication with unknown or custom drivers can indicate rootkit command channels, kernel exploit triggers, or hardware-level manipulation.",
        "mitre_id": "T1068"
    },
    {
        "category": "Ring 0 — Kernel Memory",
        "operation": "NtSystemDebugControl",
        "severity": "critical",
        "threat_type": "Kernel Debug Interface Abuse",
        "description": "NtSystemDebugControl was called — this native API provides raw kernel memory read/write, MSR access, and system state manipulation. It is used by kernel exploits and debugging rootkits to tamper with the OS kernel directly.",
        "mitre_id": "T1068"
    },
    {
        "category": "Ring 0 — Boot Persistence",
        "operation": "RegSetValue",
        "path_pattern": r"\\(BootExecute|SetupExecute|BootVerificationProgram)",
        "severity": "critical",
        "threat_type": "Boot-Level Persistence (Bootkit)",
        "description": "Boot execution registry entries were modified. These run before Windows fully loads — providing the deepest level of persistence that survives OS reinstalls and is invisible to user-mode security tools.",
        "mitre_id": "T1542.003"
    },
    {
        "category": "Ring 0 — Firmware",
        "operation": "CreateFile",
        "path_pattern": r"\\EFI\\|\\Device\\Harddisk.*Partition0",
        "severity": "critical",
        "threat_type": "EFI/Boot Partition Modification",
        "description": "Files in the EFI System Partition or raw disk partition 0 were accessed. Modification of boot components can install firmware-level rootkits (bootkits) that persist below the OS and cannot be detected by standard antivirus.",
        "mitre_id": "T1542.001"
    },
]

# ═══════════════════════════════════════════════════════════════
#  COMBINED RULE DATABASE
# ═══════════════════════════════════════════════════════════════
ALL_RULES = RING0_RULES + RING3_RULES

# Severity priority for sorting
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
SEVERITY_COLOR = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#16a34a"}


def match_rule(rule: dict, operation: str, path: str, detail: str, process_name: str) -> bool:
    """Check if a ProcMon log entry matches a threat detection rule."""
    # Operation match (required — substring, case-insensitive)
    if rule["operation"].lower() not in operation.lower():
        return False

    # Path pattern (optional regex)
    if "path_pattern" in rule and rule["path_pattern"]:
        if not re.search(rule["path_pattern"], path, re.IGNORECASE):
            return False

    # Detail pattern (optional regex)
    if "detail_pattern" in rule and rule["detail_pattern"]:
        if not re.search(rule["detail_pattern"], detail, re.IGNORECASE):
            return False

    # Process name pattern (optional regex)
    if "process_pattern" in rule and rule["process_pattern"]:
        if not re.search(rule["process_pattern"], process_name, re.IGNORECASE):
            return False

    return True


def check_known_process(process_name: str) -> tuple | None:
    """Check if a process name matches the known-malicious database.
    Returns (severity, threat_type, description) or None.
    """
    pname = process_name.lower().strip()
    for known, info in KNOWN_MALICIOUS_PROCESSES.items():
        if known.lower() in pname:
            return info
    return None
