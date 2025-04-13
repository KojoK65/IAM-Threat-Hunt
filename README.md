# 🛡️ Threat Hunt Report: Unauthorized Privilege Escalation via Local Admin Creation

## 🧰 Platforms and Tools

- **Operating System:** Windows 10 (Azure VM)  
- **Security Platform:** Microsoft Defender for Endpoint  
- **Query Language:** Kusto Query Language (KQL)  
- **Automation/Detection Tools:** PowerShell  

---

## 🎯 Scenario Overview

Security operations received alerts of potentially unauthorized account changes. It is suspected that a threat actor may have created a local admin account for persistence. This hunt investigates whether any IAM-related abuse occurred, such as:

- Creation of local admin accounts  
- Use of execution policy bypass in PowerShell  
- Script download activity through PowerShell  

> If any IAM abuse is found, the incident must be escalated to the response team.

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

**Screenshot:**  
![Step 1 Screenshot](images/step1_localadmin_creation.png)

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

**Screenshot:**  
![Step 2 Screenshot](images/step2_powershell_bypass.png)

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

**Screenshot:**  
![Step 3 Screenshot](images/step3_script_download.png)

---

## 🕒 Timeline of Events

| Time (EST) | Event |
|------------|-------|
| 08:14:22 | Local admin account created using `net.exe` |
| 08:15:09 | PowerShell launched with `-ExecutionPolicy Bypass` |
| 08:15:47 | PowerShell attempted to download a remote `.ps1` script |

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
