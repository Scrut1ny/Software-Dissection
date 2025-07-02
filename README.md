<div align="center">

🕵️ Software Analysis 🕵️

</div>

---

#### Recommended Software
- Websites
    - [Decompiler Explorer](https://dogbolt.org/)
    - [SQLite Viewer Web App](https://sqliteviewer.app/)
- Software
    - [Process Informer](https://github.com/winsiderss/systeminformer)
    - [PE-Bear (Lightweight PE Analyzer)](https://github.com/hasherezade/pe-bear)
    - [Detect It Easy (DIE)](https://github.com/horsicq/DIE-engine)
    - [Ghidra (Advanced Reverse Engineering)](https://github.com/NationalSecurityAgency/ghidra)
    - [x64dbg (Dynamic Debugging)](https://github.com/x64dbg/x64dbg)

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
