<div align="center">

# 🩸 Active Directory Enumeration Lab – BloodHound & SharpHound

### Attack Path Discovery · Nested Group Misconfiguration · Privilege Creep · Remediation · Validation

![Domain](https://img.shields.io/badge/Type-AD%20Enumeration%20%26%20Attack%20Path%20Analysis-purple?style=for-the-badge)
![Tool](https://img.shields.io/badge/Tool-BloodHound%20%7C%20SharpHound-red?style=for-the-badge)

<img src="https://img.shields.io/badge/Domain-biksec.com-blue?style=flat-square" />
<img src="https://img.shields.io/badge/Finding-Nested%20Group%20Privilege%20Creep-red?style=flat-square" />
<img src="https://img.shields.io/badge/Severity-High-critical?style=flat-square" />
<img src="https://img.shields.io/badge/MITRE-T1069%20%7C%20T1078%20%7C%20T1484-orange?style=flat-square" />
<img src="https://img.shields.io/badge/Remediation-Nested%20Memberships%20Removed-blue?style=flat-square" />
<img src="https://img.shields.io/badge/Validation-Attack%20Path%20Removed-brightgreen?style=flat-square" />

---
## 📄 Full Lab Walkthrough — Proof of Work

| File | Description |
| --- | --- |
| [AD_Enumeration_BloodHound_SharpHound_Lab_Report.docx](./AD_Enumeration_BloodHound_SharpHound_Lab_Report.docx) | Hands-on lab walkthrough with screenshots |

**Prepared by:** Bikash Raya


</div>

---



## 📋 Overview

This lab covers Active Directory enumeration and attack path analysis using **BloodHound** and **SharpHound** — completing a full cycle of collection, analysis, finding documentation, remediation, and validation.

**SharpHound** was run on the Windows domain controller to collect AD relationship data. **BloodHound** was installed on Kali Linux to ingest that data, build a graph in Neo4j, and visualise attack paths across the domain.

A nested group misconfiguration was deliberately introduced — a common real-world AD security gap where a low-privileged user (Braya) inherits Server Admins access through a chain of three group memberships. BloodHound surfaced the privilege escalation path immediately in a graph that is completely invisible in standard AD tools. The finding was documented, remediated, and confirmed resolved through a final SharpHound collection and re-import.

---

## 🛠️ Technologies Used

* SharpHound v2.13.0 (Windows — AD data collection)
* BloodHound — SpecterOps (Kali Linux — graph analysis)
* Neo4j 4.4.26 (graph database backend)
* Kali Linux (analysis machine)
* Windows Server 2022 — BIKSEC-DC01 (biksec.com domain)
* SCP / SSH (data transfer)
* Cypher Query Language

---

## 🧪 Lab Environment

| Component | Value |
| --- | --- |
| Domain | biksec.com |
| Domain Controller | BIKSEC-DC01 — Windows Server 2022 |
| Analysis Machine | Kali Linux (192.168.219.30) |
| SharpHound | v2.13.0 — run on Windows domain controller |
| BloodHound | SpecterOps — installed on Kali Linux |
| Graph Database | Neo4j 4.4.26 on Kali Linux |
| Target User | Braya (Bimal Raya) — low-privileged domain user |

---

## 🌐 Architecture

```
[BIKSEC-DC01 — Windows Server 2022]
  biksec.com Active Directory
         │
         │  SharpHound.exe -c All
         │  Collects: Users, Groups, ACLs, Sessions, GPOs, Trusts
         │  Output: 20260712222836_BloodHound.zip
         │
         │  SCP → kali@192.168.219.30:/home/kali/Desktop/
         ▼
[Kali Linux — 192.168.219.30]
  Neo4j 4.4.26 (graph database)
  BloodHound UI → http://127.0.0.1:8080
         │
         │  Import ZIP → Build graph → Cypher queries
         ▼
  Finding: Braya → HelpDesk Team → IT Operations → Server Admins
         │
         │  Remediate → Re-run SharpHound → Re-import
         ▼
  Validation: Attack path no longer present ✅
```

---

## 🔬 Lab Phases

### Phase 1 — SharpHound Data Collection (Windows)

SharpHound was downloaded on the Windows domain controller. Windows Defender real-time protection and SmartScreen were temporarily disabled to allow the download.

SharpHound was run to collect AD data:

```powershell
SharpHound.exe -c All
# Output: 20260712222836_BloodHound.zip
```

SharpHound collects: all users, computers, groups, nested group memberships, ACL permissions, GPO links, OU structure, active sessions, and domain trusts — packaged into a ZIP ready for BloodHound.

---

### Phase 2 — Transfer to Kali Linux

SSH was configured on Kali to receive the file:

```bash
sudo apt-get install ssh
sudo systemctl enable ssh
sudo systemctl start ssh
```

SharpHound ZIP transferred from Windows to Kali:

```bash
scp "C:\Users\Administrator\Downloads\20260712222836_BloodHound.zip" kali@192.168.219.30:/home/kali/Desktop/
# 20260712222836_BloodHound.zip 100% 31KB 1.9MB/s
```

---

### Phase 3 — BloodHound Setup on Kali

```bash
# Start Neo4j graph database
sudo neo4j console
# Listening on localhost:7474 (HTTP) and localhost:7687 (Bolt)

# Start BloodHound
sudo bloodhound-start
# Web UI: http://127.0.0.1:8080
```

BloodHound configuration file updated with Neo4j credentials:
```bash
sudo nano /etc/bhapi/bhapi.json
```

---

### Phase 4 — Initial Domain Enumeration

SharpHound ZIP imported into BloodHound. Cypher queries run to explore the domain:

**All Domain Admin members (including nested):**
```cypher
MATCH p = (t:Group)<-[:MemberOf*1..]-(a)
WHERE (a:User or a:Computer) and t.objectid ENDS WITH '-512'
RETURN p LIMIT 1000
```

**OU structure:**
```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:OU)
RETURN p LIMIT 1000
```

---

### Phase 5 — Nested Group Misconfiguration

A nested group misconfiguration was introduced in biksec.com to simulate real-world privilege creep:

**Groups created:** HelpDesk Team · IT Operations · Server Admins (in a Groups OU)

**User created:** Bimal Raya (`Braya`) — intended as a low-privileged HelpDesk user

**Misconfigured chain:**
```
Braya
  └─ MemberOf → HelpDesk Team
                  └─ MemberOf → IT Operations
                                  └─ MemberOf → Server Admins
```

Braya has no direct Server Admins assignment — but inherits full permissions through a 3-hop chain.

---

### Phase 6 — Attack Path Discovered

SharpHound re-run after misconfiguration, ZIP transferred to Kali and imported into BloodHound.

### Finding: Excessive Privilege Through Nested Group Membership

| | |
|--|--|
| **Finding** | Excessive Privilege Through Nested Group Membership (Privilege Creep) |
| **Severity** | 🔴 High |
| **Attack Path** | `Braya → HelpDesk Team → IT Operations → Server Admins` |
| **Risk** | A compromised HelpDesk account gains Server Admins access through nested membership — with no direct assignment visible on the user. Completely invisible in standard AD tools, immediately apparent in BloodHound. |
| **MITRE** | T1069 Permission Groups Discovery · T1078 Valid Accounts · T1484 Domain Policy Modification |

---

### Phase 7 — Remediation

Excessive nested memberships removed — principle of least privilege applied:

| Action | Result |
| --- | --- |
| Removed HelpDesk Team from IT Operations | First hop in chain broken |
| Removed IT Operations from Server Admins | Second hop in chain broken |
| Retained Braya in HelpDesk Team | Legitimate role access preserved |

**Result:** `Braya → HelpDesk Team` only. No path to Server Admins.

---

### Phase 8 — Validation

SharpHound re-run after remediation:

```powershell
SharpHound.exe -c All
```

Updated ZIP imported into BloodHound.

✅ Braya's node shows HelpDesk Team membership only
✅ No path to Server Admins exists in the graph
✅ Privilege escalation path confirmed removed

---

## 🎯 MITRE ATT&CK

| Technique | Name | Relevance |
| --- | --- | --- |
| T1069 | Permission Groups Discovery | BloodHound enumerates all group memberships and effective permissions |
| T1078 | Valid Accounts | Low-privileged account (Braya) gains elevated access through inheritance |
| T1484 | Domain Policy Modification | Nested group memberships create unintended privilege structure |

---

## 🎯 Skills Demonstrated

* SharpHound AD Data Collection
* BloodHound Graph Analysis & Attack Path Visualisation
* Cypher Query Language (Neo4j)
* Privilege Escalation Path Discovery
* Nested Group Misconfiguration Analysis
* Privilege Creep Identification & Documentation
* SSH Configuration & SCP File Transfer (Kali Linux)
* Active Directory Group Management
* Principle of Least Privilege Application
* MITRE ATT&CK Technique Mapping
* Remediation & Validation Cycle

---

## 🎯 Key Takeaway

> SharpHound collected AD data from biksec.com and BloodHound rendered the domain relationships as an attack graph on Kali Linux. A nested group misconfiguration gave a low-privileged user indirect Server Admins access through a 3-hop chain — invisible in standard AD tools, immediately visible in BloodHound. The finding was documented as High severity, remediated by removing the excessive group memberships, and validated through a final SharpHound collection confirming the path is gone. This is the same workflow used by penetration testers and AD security engineers to find and fix privilege escalation paths in enterprise environments.

---

## 🔗 Related Projects

> Part of the **Bikash Security Lab** series:
> * [System Hardening Lab — Linux, Windows Server & AD](https://github.com/Bikash-Raya/system-hardening-lab-linux-windows-active-directory)
> * [Microsoft Sentinel & Defender XDR — SOC IR Lab](https://github.com/Bikash-Raya/Sentinel-Defender-XDR-SOC-Incident-Response-lab)
> * [Nessus Vulnerability Management Lab](https://github.com/Bikash-Raya/Nessus-Vulnerability-Management-Lab)

---

> 📄 Thanks for reading! For a full hands-on walkthrough of this lab with screenshots — [download the lab report here](./AD_Enumeration_BloodHound_SharpHound_Lab_Report.docx)

---

## 🔗 Connect With Me

<div align="center">

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/bikash-raya/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/Bikash-Raya)

</div>

---

<div align="center">

⭐ If you find this project useful, feel free to star the repository ⭐

</div>
