## Hybrid SOC Homelab – Raspberry Pi 5 + Microsoft Sentinel (SIEM + SOAR)

> A hybrid security monitoring homelab using Raspberry Pi 5 (Ubuntu 24.04) integrated with Microsoft Sentinel for end-to-end SOC operations: log ingestion, detection engineering, automated incident response (SOAR), and MITRE ATT&CK-aligned threat detection.


---

## 📌 Project Overview

This project demonstrates a complete SOC pipeline — from raw syslog on a physical Linux endpoint through to automated Discord alerting — using Microsoft Sentinel as the SIEM/SOAR platform.

The lab covers four pillars of SOC operations:

1. **Log Ingestion** — Azure Arc + AMA agent forwarding Linux syslog to a Log Analytics Workspace
2. **Detection Engineering** — KQL analytics rules detecting SSH brute-force, credential access, and privilege escalation
3. **Incident Creation** — Sentinel scheduled rules generating incidents with entity mapping
4. **Automated Response (SOAR)** — Logic App playbook triggered by Automation Rules, pushing formatted alerts to Discord via webhook


---

## 🎯 Project Objectives

- Build a low-cost hybrid SOC monitoring lab
- Register Raspberry Pi as an Azure Arc-enabled machine
- Deploy Azure Monitor Agent (AMA)
- Configure Data Collection Rule (DCR)
- Ingest Linux syslog into Microsoft Sentinel
- Simulate authentication attack scenarios
- Develop detection logic using KQL
- Map detections to MITRE ATT&CK framework

---

## 🏛 Architecture


```
┌─────────────────────────────────────────────────────────────────────┐
│                        DETECTION & RESPONSE                         │
│                                                                     │
│  Raspberry Pi 5 (Ubuntu 24.04)                                      │
│  └── SSH / Syslog events                                            │
│          │                                                          │
│          ▼                                                          │
│  Azure Arc (Hybrid Machine Registration)                            │
│          │                                                          │
│          ▼                                                          │
│  Azure Monitor Agent (AMA)                                          │
│          │                                                          │
│          ▼                                                          │
│  Data Collection Rule (auth / authpriv / daemon)                    │
│          │                                                          │
│          ▼                                                          │
│  Log Analytics Workspace                                            │
│          │                                                          │
│          ▼                                                          │
│  Microsoft Sentinel ──── Analytics Rules (KQL)                      │
│          │                      │                                   │
│          ▼                      ▼                                   │
│     Incidents ◄──── Entity Mapping (IP, Host, Account)              │
│          │                                                          │
│          ▼                                                          │
│  Automation Rule (trigger on incident creation)                     │
│          │                                                          │
│          ▼                                                          │
│  Logic App Playbook (SOAR)                                          │
│          │                                                          │
│          ▼                                                          │
│  Discord Webhook ── Real-time alert with incident details           │
└─────────────────────────────────────────────────────────────────────┘
```
---

## 🖥 Lab Environment

| Component | Details |
|-----------|---------|
| Hardware | Raspberry Pi 5 |
| OS | Ubuntu 24.04 LTS |
| Cloud Platform | Microsoft Azure |
| SIEM | Microsoft Sentinel |
| SOAR | Azure Logic Apps + Sentinel Automation Rules |
| Log Source | Linux Syslog (auth, authpriv, daemon) |
| Agent | Azure Monitor Agent (AMA) |
| Log Ingestion | Data Collection Rule (DCR) |
| Notification | Discord Webhook |


---

## ⚙ Implementation Steps

### 1. Ubuntu Installation & Configuration

- Installed Ubuntu 24.04 LTS on Raspberry Pi 5
- Configured SSH access
- Verified internet connectivity

### 2. Azure Arc Onboarding

- Registered Raspberry Pi as Azure Arc-enabled machine
- Authenticated via Azure portal
- Verified status:

```bash
sudo azcmagent show
```
Status: Connected

### 3. Azure Monitor Agent Deployment

- Installed AMA extension from Azure Portal
- Verified service:

```bash
systemctl status azuremonitoragent
```
Status: Active (running)

### 4. Data Collection Rule Configuration

Configured DCR to collect:

- `LOG_AUTH` — authentication events
- `LOG_AUTHPRIV` — privileged authentication (sudo, SSH)
- `LOG_DAEMON` — system service events

Minimum log level: `LOG_INFO`
Destination: Log Analytics Workspace
Assigned to the Azure Arc Raspberry Pi resource.

---

## Threat Simulation

Simulated brute-force login attempts using invalid SSH credentials:

```bash
# Repeated failed login attempts to generate auth failure events
for i in $(seq 1 10); do ssh invaliduser@localhost; done
```

This generates `Failed password` entries in syslog, which are ingested into Sentinel via the DCR pipeline.

---

## Detection Engineering

All KQL queries are stored in the [`Detection-Rules/`](./Detection-Rules/) directory.

### Brute Force Detection (with Entity Extraction)

```kql
Syslog
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password"
| parse SyslogMessage with * "Failed password for " TargetUser " from " SourceIP " port " *
| summarize
    FailedAttempts = count(),
    TargetUsers = make_set(TargetUser),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SourceIP, Computer, bin(TimeGenerated, 10m)
| where FailedAttempts >= 3
| project TimeGenerated, Computer, SourceIP, FailedAttempts, TargetUsers, FirstSeen, LastSeen
```

This improved query extracts the **source IP** and **target username** directly from the syslog message — giving the analyst actionable triage data without having to dig through raw logs.

### Successful Login After Brute Force (T1078 — Valid Accounts)

```kql
let BruteForceIPs =
    Syslog
    | where ProcessName == "sshd"
    | where SyslogMessage has "Failed password"
    | parse SyslogMessage with * "from " SourceIP " port " *
    | summarize FailedAttempts = count() by SourceIP, bin(TimeGenerated, 30m)
    | where FailedAttempts >= 3
    | distinct SourceIP;
Syslog
| where ProcessName == "sshd"
| where SyslogMessage has "Accepted password"
| parse SyslogMessage with * "Accepted password for " TargetUser " from " SourceIP " port " *
| where SourceIP in (BruteForceIPs)
| project TimeGenerated, Computer, SourceIP, TargetUser, SyslogMessage
```

Detects when a source IP that was brute-forcing actually **succeeds** — this is a high-severity indicator of credential compromise.

### Privilege Escalation via Sudo

```kql
Syslog
| where Facility == "authpriv"
| where SyslogMessage has "sudo" and SyslogMessage has "COMMAND="
| parse SyslogMessage with * "USER=" ExecutingUser " ; COMMAND=" ExecutedCommand
| project TimeGenerated, Computer, ExecutingUser, ExecutedCommand
| sort by TimeGenerated desc
```

Monitors for privilege escalation activity on the endpoint.

### Authentication Event Investigation (Triage)

```kql
Syslog
| where Facility in ("auth", "authpriv")
| where ProcessName in ("sshd", "sudo", "login")
| project TimeGenerated, Computer, ProcessName, Facility, SyslogMessage
| sort by TimeGenerated desc
| take 50
```

---

## Analytics Rule Configuration

Created a Scheduled Analytics Rule in Microsoft Sentinel:

| Setting | Value |
|---------|-------|
| Query | Brute-force detection KQL (with entity extraction) |
| Frequency | Every 5 minutes |
| Lookup period | Last 5 minutes |
| Trigger threshold | FailedAttempts >= 3 |
| Entity mapping | IP address (SourceIP), Host (Computer) |
| Incident creation | Enabled |

The analytics rule runs every 5 minutes and evaluates the previous 5 minutes of data. The query groups events into 10-minute bins, aggregating the 5-minute evaluation window into a single detection bucket.

---

## SOAR — Automated Incident Response

This is the automated response layer that closes the detection-to-response loop.

### How It Works

1. **Analytics Rule** fires → creates a Sentinel **Incident**
2. **Automation Rule** triggers on incident creation (filtered to "Brute Force attack" analytics rule)
3. **Logic App Playbook** executes with Managed Identity authentication
4. Playbook extracts incident fields (title, severity, timestamp, IP address) using null-safe dynamic expressions
5. Sends a formatted POST request to a **Discord webhook**
6. SOC analyst receives real-time notification with actionable context

### Playbook Details

| Component | Implementation |
|-----------|---------------|
| Trigger | Microsoft Sentinel Incident Trigger |
| Authentication | System-Assigned Managed Identity |
| IAM Role | Microsoft Sentinel Responder |
| Action | HTTP POST to Discord webhook |
| Null handling | `if(empty(...))` expressions for missing entities |
| Template | [`playbook-logic.json`](./Automation-Playbooks/BruteForce-Discord-Playbook/playbook-logic.json) (sanitised) |

### Discord Alert Format

```
🚨 Sentinel Incident Triggered!

Title: Brute Force attack
Severity: Medium
Created: 2026-02-18T10:04:53.67Z
IP Address: X.X.X.X
```

See full SOAR documentation: [`Automation-Playbooks/BruteForce-Discord-Playbook/README.md`](./Automation-Playbooks/BruteForce-Discord-Playbook/README.md)

---

## MITRE ATT&CK Mapping

| Technique ID | Technique | Detection |
|-------------|-----------|-----------|
| T1110 | Brute Force | SSH failed password threshold detection |
| T1078 | Valid Accounts | Successful login from brute-force source IP |
| T1548 | Abuse Elevation Control Mechanism | Sudo command execution monitoring |

---

## 📸 Screenshots

### 1️⃣ Azure Arc Machine Registration

<img width="3356" height="1924" alt="image" src="https://github.com/user-attachments/assets/5d02bb03-5d89-4d8b-9c16-41ee5b5918d9" />



---

### 2️⃣ Data Collection Rule Configuration

<img width="3354" height="1926" alt="image" src="https://github.com/user-attachments/assets/413aed55-ba77-441a-beae-c80b3d1e2a57" />
<img width="3360" height="1928" alt="image" src="https://github.com/user-attachments/assets/108d5a41-1d4b-4853-b7c3-cb86a66e4216" />




---

### 3️⃣ Sentinel Log Ingestion

<img width="3356" height="1924" alt="image" src="https://github.com/user-attachments/assets/e26155df-fa92-4857-99e2-9c9ded23de0b" />


---

### 4️⃣ Analytics Rule Configuration

<img width="3354" height="1924" alt="image" src="https://github.com/user-attachments/assets/9354e0e7-32ca-4add-957e-3385d3f98377" />


---

### 5️⃣ Generated Security Incident

<img width="3360" height="1926" alt="image" src="https://github.com/user-attachments/assets/b243c005-34e0-4869-b21f-3471fea95ff3" />

---

### 6️⃣ Logic App Designer
![Logic App designer](https://github.com/user-attachments/assets/cc09bb4c-5650-4c4b-9b87-0bd7f28717aa)

---  

### 7️⃣ Automation Rule
<img width="3350" height="1922" alt="image" src="https://github.com/user-attachments/assets/e025ec40-c5ad-4a0a-8d9d-723beb469c20" />

---

### 8️⃣ Discord Alert
<img width="3358" height="1930" alt="image" src="https://github.com/user-attachments/assets/9ef0411d-84f6-46fc-a8d6-c351f5129cdd" />

---

### 9️⃣ Run History
<img width="3360" height="824" alt="image" src="https://github.com/user-attachments/assets/57d713bd-e8c1-41d1-a0c9-48038ba35a96" />

---


## ⚠ Challenges & Lessons Learned

- Data Collection Rule must be configured and assigned before log ingestion begins — there is no retroactive collection
- Workspace scope selection in Azure Portal affects DCR visibility; selecting the wrong scope hides the rule
- Log ingestion delay of 5–15 minutes can occur after initial AMA deployment
- Correct syslog facility selection (auth vs authpriv) is critical — choosing the wrong facility means missing SSH events entirely
- Logic App Managed Identity requires explicit IAM role assignment (Sentinel Responder) or the playbook silently fails
- Discord webhook payload must use the `content` key, not `text` — a common integration mistake

---

## 🚀 Future Improvements

- Integrate Suricata IDS alerts into Sentinel for network-layer visibility
- Add IP reputation enrichment using TI (Threat Intelligence) feeds
- Create Sentinel Workbook dashboards for visual SOC monitoring
- Simulate lateral movement and detect it with additional KQL rules
- Add a second SOAR playbook for automated IP blocking via NSG rules
- Implement email notification channel as a fallback to Discord

---

## 🧠 Skills Demonstrated

- Hybrid Cloud Security Architecture (Azure Arc + on-prem Linux)
- Microsoft Sentinel SIEM deployment and configuration
- SOAR implementation using Logic Apps and Automation Rules
- Azure Monitor Agent and Data Collection Rule pipeline design
- KQL query development with entity extraction (parse operator)
- Detection engineering with multiple analytics rules
- MITRE ATT&CK technique mapping (T1110, T1078, T1548)
- Incident creation, triage, and investigation workflows
- Webhook-based automated alerting (Discord)
- ARM template export and sanitisation for public sharing

---
