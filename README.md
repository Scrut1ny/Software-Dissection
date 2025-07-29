<div align="center">

# 🕵️ Software Analysis 🕵️

</div>

A categorized collection of tools, websites, and resources for reverse engineering software, binaries, and systems — including static analysis, dynamic analysis, decompilation, sandboxing, and more.

---

## 🕸️ Web-Based Tools

### 🧠 Analysis / Decompilation
- [Decompiler Explorer](https://dogbolt.org/) – Compare how different compilers decompile code.
- [Godbolt Compiler Explorer](https://godbolt.org/) – View assembly output from C/C++ code.
- [HexEd.it](https://hexed.it/) – Online hex editor for binary inspection.

### 📂 File / Data Inspection
- [SQLite Viewer Web App](https://sqliteviewer.app/) – View and explore `.sqlite` databases.
- [JS Beautifier](https://beautifier.io/) – Deobfuscate and format JavaScript.

---

## 🧰 Static Analysis Tools

### 🧠 Decompilers & Disassemblers
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) – Advanced reverse engineering suite.
- [IDA Free / IDA Pro](https://hex-rays.com/ida-free/) – Industry-standard disassembler.
- [Cutter](https://github.com/rizinorg/cutter) – GUI frontend for Rizin (Radare2 fork).
- [dnSpy](https://github.com/dnSpyEx/dnSpy) – Decompiler/debugger for .NET executables.
- [JD-GUI](http://java-decompiler.github.io/) – Java `.jar` decompiler.
- [CFR](https://github.com/leibnitz27/cfr) – Another powerful Java decompiler.

### 📦 PE & Binary Inspection
- [PE-Bear](https://github.com/hasherezade/pe-bear) – Lightweight PE file analyzer.
- [Detect It Easy (DIE)](https://github.com/horsicq/DIE-engine) – Detect packers, compilers, and obfuscators.
- [Binwalk](https://github.com/ReFirmLabs/binwalk) – Analyze and extract binary firmware images.
- [Resource Hacker](http://www.angusj.com/resourcehacker/) – Inspect/modify EXE/DLL resource files.
- `strings` – Extract readable text from binaries (GNU or Sysinternals version).

---

## 🧪 Dynamic Analysis Tools

### 🐞 Debuggers
- [x64dbg](https://github.com/x64dbg/x64dbg) – Debugger for 64-bit and 32-bit Windows executables.
- [OllyDbg](http://www.ollydbg.de/) – 32-bit debugger, classic reverse engineering tool.
- [Immunity Debugger](https://debugger.immunityinc.com/) – Debugger with Python scripting.

### 📡 System Monitoring
- [System Informer (formerly Process Hacker)](https://github.com/winsiderss/systeminformer) – Process viewer and system monitor.
- [Process Monitor (ProcMon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) – Monitors file, registry, and process activity.
- [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) – Advanced task manager from Sysinternals.
- [API Monitor](http://www.rohitab.com/apimonitor) – View real-time API calls.
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) – System activity logging for security analysis.

---

## 🌐 Network Monitoring Tools

- [Wireshark](https://www.wireshark.org/) – Network packet analyzer.
- [Fiddler Classic](https://www.telerik.com/fiddler/fiddler-classic) – HTTP/HTTPS debugging proxy.
- [mitmproxy](https://mitmproxy.org/) – Intercept, modify, and replay HTTP(S) traffic.
- [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview) – Monitor open TCP/UDP connections.

---

## 💻 Virtualization & Sandboxing

- [VMware Workstation Player](https://www.vmware.com/products/workstation-player.html) – Free VM for Windows/Linux.
- [VirtualBox](https://www.virtualbox.org/) – Open-source virtualization software.
- [Sandboxie Plus](https://github.com/sandboxie-plus/Sandboxie) – Run applications in isolated sandbox.

---

## 🧬 Instrumentation & Hooking

- [Frida](https://frida.re/) – Dynamic instrumentation toolkit for runtime hooking.
- [Cheat Engine](https://www.cheatengine.org/) – Memory scanner and debugger.
- [ScyllaHide](https://github.com/x64dbg/ScyllaHide) – Anti-anti-debug plugin for x64dbg.
- [Syscall Monitor](https://github.com/SamuelTulach/syscall-monitor) – Monitor and log Windows system calls.

---

## 📋 Automation & Scripting

- [Python + Capstone](http://www.capstone-engine.org/) – Disassembly engine with Python bindings.
- [uncompyle6](https://github.com/rocky/python-uncompyle6) – Decompile `.pyc` Python bytecode.
- [Volatility](https://www.volatilityfoundation.org/) – Memory forensics and RAM dump analysis.

---

## 📚 Learning Resources

- [Malware Unicorn’s RE 101 Workshop](https://malwareunicorn.org/workshops/re101.html) – Beginner reverse engineering course.
- [Practical Malware Analysis](https://nostarch.com/malware) – Classic textbook on malware reverse engineering.
- [OpenSecurityTraining.info](https://opensecuritytraining.info/) – Free courses on RE, exploitation, and more.
- [RE for Beginners](https://beginners.re/) – Open-source reverse engineering book.

---

**Disclaimer**: Use responsibly. Some of these tools may be used for malicious purposes — always ensure you're working within legal and ethical boundaries.

---

<details>
<summary>Pearson VUE: OnVUE</summary>

- [Sameple Exam/System Test](https://vueop.startpractice.com/)
- [System Requirements](https://home.pearsonvue.com/Standalone-pages/System-requirements-PVBL.aspx)

- Exam Content & Special Configurations (SDS)
```
https://securedelivery-hs-prd-1.pearsonvue.com/SecureDeliveryService
```

- Application location:
```batch
%APPDATA%\OnVUE\BrowserLock.exe
```

- Log file location:
```batch
%LOCALAPPDATA%\BrowserLock\log
```

- Commands it runs
```powershell
# Obtains NetConnectionID
wmic nic where "NetConnectionStatus = 2" get NetConnectionID /value

# Obtains USB FriendlyName
powershell.exe Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match '^USB' }

# Obtains Display/Monitor FriendlyName
powershell.exe -Command "Get-WmiObject -Namespace 'root\WMI' -Class 'WMIMonitorID' | ForEach-Object -Process { if($_.UserFriendlyName) { ([System.Text.Encoding]::ASCII.GetString($_.UserFriendlyName)).Replace('$([char]0x0000)','') } }"

# Obtains running processes
powershell.exe /c Get-CimInstance -className win32_process | select Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath

# Obtains MachineGUID
powershell (Get-ItemProperty registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\ -Name MachineGuid).MachineGUID

# Obtains system hostname
C:\Windows\system32\cmd.exe /c hostname
```

- Hypervisor System Checks (in log file):
```
# LOG:
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] VM Allowed flag value from forensics is vmAllowedForensic=false
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] Multiple Monitor Allowed flag value from forensics is multiMonitorAllowedForensic=false
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] VPN Allowed flag value from forensics is vpnAllowedForensic=true
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] Shutdown file monitor started
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] VM configuration received from SDS will be applied for validation
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] VM detection value is: vmDetectConfig=true
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] Multiple monitor configuration received from SDS will be applied for validation
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] Multiple monitor detection value is: multipleMonitorDetectConfig=true
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] VPN configuration received from forensics will be applied for validation
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] VPN detection value is: vpnDetectConfig=false
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] USB mass storage detection value is: usbDetectConfig=false
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] Minimum browserlock version required: 2304 
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] Current browserlock version: 2402.1.1 
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] Check if Browserlock running on VM: {DMI type 1 (System Information) - Product Name}, {DMI type 2 (Base Board Information) - Serial Number}, runningOnVM=false
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] VM check: diskSize=499 GB
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] Browserlock is not running on virtual machine
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] Display HDCP supported check: hdcpSupported=true
XXXX-XX-XX XX:XX:XX.XXX-XXXX [BROWSER LOCK] [INFO] Number of display devices connected: AWT=1, Physical=1, Physical/Virtual=1, Duplicate=1

# BrowserLock Booleon Variables
- hdcpSupported
- multiMonitorAllowedForensic
- multipleMonitorDetectConfig
- runningOnVM
- usbDetectConfig
- vmAllowedForensic
- vmDetectConfig
- vpnAllowedForensic
- vpnDetectConfig
```

![image](https://github.com/Scrut1ny/Hypervisor-Phantom/assets/53458032/af144f9c-e69b-4998-8b44-16c876612c25)

</details>

---




---


<details>
<summary>Respondus: LockDown Browser</summary>

- https://autolaunch.respondus2.com/MONServer/ldb/tou_violation_warning.do?ref=
- https://autolaunch.respondus2.com/MONServer/ldb/preview_launch.do

</details>

---
