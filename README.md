<p align="center">
  <img src="https://github.com/user-attachments/assets/85b444e7-5edd-4272-ba92-76b273cfdea1" alt="Threat Hunt Diagram" width="500"/>
</p>

# Threat Hunt Report: Unauthorized Privilege Escalation via Local Admin Creation

## 🧰 Platforms and Tools

- **Operating System:** Windows 10 (Azure VM)  
- **Security Platform:** Microsoft Defender for Endpoint  
- **Query Language:** Kusto Query Language (KQL)  
- **Automation/Detection Tools:** PowerShell  

---

## - [ 🎯 Scenario Creation](https://github.com/KojoK65/IAM-Threat-Hunt/blob/main/IAM-Threat-Hunt-Event-Creation.md)

---

## 🔍 Investigation Plan

| Step | Objective |
|------|-----------|
| 1️⃣ | Detect `net.exe` or `net1.exe` commands creating new local admins |
| 2️⃣ | Identify suspicious PowerShell usage (e.g., execution policy bypass) |
| 3️⃣ | Search for any PowerShell-initiated outbound traffic (e.g., .ps1 downloads) |

---

## 🧪 Step-by-Step Analysis

### ✅ Step 1: Detect Local Admin Account Creation

We searched for use of `net.exe` or `net1.exe` to add users to the local Administrators group.

**KQL Query Used:**
```kusto
DeviceProcessEvents
| where FileName =~ "net.exe" or FileName =~ "net1.exe"
| where ProcessCommandLine has "localgroup administrators" and ProcessCommandLine has "add"
| where Timestamp > ago(1d)
```

<img width="700" alt="Screen Shot 2025-04-13 at 6 00 40 PM" src="https://github.com/user-attachments/assets/8f294dea-ec8c-4fa5-9865-6f3c4510b824" />



---

### ✅ Step 2: Identify PowerShell Execution Policy Bypass

Suspicious PowerShell command-line flags were detected, especially `-ExecutionPolicy Bypass`.

**KQL Query Used:**
```kusto
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-ExecutionPolicy Bypass"
| where Timestamp > ago(1d)
```
<img width="855" alt="Screen Shot 2025-04-13 at 6 08 17 PM" src="https://github.com/user-attachments/assets/bf1eb1a8-5d25-4f3c-9572-0ff75b878b39" />

---

### ✅ Step 3: Detect Script Download via PowerShell

We searched `DeviceNetworkEvents` for signs of PowerShell initiating downloads from URLs.

**KQL Query Used:**
```kusto
DeviceNetworkEvents
| where RemoteUrl has "google.com" or RemoteUrl has ".ps1"
| where InitiatingProcessFileName =~ "powershell.exe"
| where Timestamp > ago(1d)
```

<img width="883" alt="Screen Shot 2025-04-13 at 6 09 32 PM" src="https://github.com/user-attachments/assets/90b5ff88-3b19-4723-8a52-679b83c8f6d7" />


---

## 🕒 Timeline of Events

| Time (EST) | Event |
|------------|-------|
| 05:10:22 | Local admin account created using `net.exe` |
| 05:14:09 | PowerShell launched with `-ExecutionPolicy Bypass` |
| 05:37:47 | PowerShell attempted to download a remote `.ps1` script |

---

## 📌 Summary

This investigation confirmed a potential misuse of Identity and Access Management (IAM) privileges. The use of administrative tools and PowerShell scripting points to a deliberate attempt to escalate privileges and possibly establish persistence.

The incident is consistent with early-stage lateral movement and privilege escalation techniques and has been escalated for further response and containment.

---

## 🚨 Response Actions

- ✅ Flagged endpoint for SOC investigation  
- ✅ Removed suspicious local admin account  
- ✅ Rotated credentials and applied LAPS  
- ✅ Logged PowerShell activity for long-term monitoring  
- ✅ Added IPs and script names to threat detection watchlist  

---

## 📁 Artifacts Collected

- 📄 **KQL Queries Used:**
  - Detection of `net.exe` or `net1.exe` account creation commands
  - Detection of PowerShell execution policy bypass
  - Detection of PowerShell download activity

- 🧾 **Microsoft Defender Logs:**
  - Command line arguments and timestamps related to suspicious activity
  - Endpoint process telemetry from `DeviceProcessEvents` and `DeviceNetworkEvents`

- 🌐 **PowerShell Download Attempts:**
  - URLs accessed by `powershell.exe`
  - Associated IPs and response codes

---

## 🧠 Lessons Learned

- 🔐 Ensure LAPS (Local Administrator Password Solution) is enforced and regularly audited on all endpoints  
- 🚨 Configure alerts for:
  - Execution policy bypass usage in PowerShell  
  - Changes to the local Administrators group  

- 📊 Implement ongoing monitoring of:
  - PowerShell logs (command-line, module loads)  
  - Unusual network behavior associated with script execution  
  - Endpoint privilege escalation activity patterns  
