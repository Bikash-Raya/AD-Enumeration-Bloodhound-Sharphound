<div align="center">

# 🩸 Active Directory Enumeration Lab – BloodHound & SharpHound

### Attack Path Discovery · Nested Group Misconfiguration · Privilege Escalation · Remediation

![Domain](https://img.shields.io/badge/Type-AD%20Enumeration%20%26%20Attack%20Path%20Analysis-purple?style=for-the-badge)
![Tool](https://img.shields.io/badge/Tool-BloodHound%20%7C%20SharpHound-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Finding-Privilege%20Escalation%20Path%20Resolved-brightgreen?style=for-the-badge)

<img src="https://img.shields.io/badge/Domain-biksec.com-blue?style=flat-square" />
<img src="https://img.shields.io/badge/Finding-Nested%20Group%20Privilege%20Creep-red?style=flat-square" />
<img src="https://img.shields.io/badge/Severity-High-critical?style=flat-square" />
<img src="https://img.shields.io/badge/MITRE-T1069%20%7C%20T1078%20%7C%20T1484-orange?style=flat-square" />
<img src="https://img.shields.io/badge/Validation-Attack%20Path%20Removed-brightgreen?style=flat-square" />

---

**Prepared by:** Bikash Raya
**Project Type:** Active Directory Enumeration & Attack Path Analysis — BloodHound / SharpHound

</div>

---

## 📁 Repository Structure

| File | Description |
| --- | --- |
| [AD_Enumeration_BloodHound_SharpHound_Lab_Report.docx](./AD_Enumeration_BloodHound_SharpHound_Lab_Report.docx) | Complete lab report with all screenshots embedded |
| README.md | Project overview |

---

## 📋 Overview

This lab demonstrates Active Directory enumeration and attack path analysis using **BloodHound** and **SharpHound** — the same tools used by penetration testers and red teams to identify privilege escalation paths within Active Directory environments.

The lab follows a complete offensive-to-defensive cycle:

* 🔍 **Enumerate** — SharpHound collected comprehensive AD data from the biksec.com domain
* 📊 **Analyse** — BloodHound visualised domain relationships and attack paths using graph analysis
* ⚙️ **Simulate** — A nested group misconfiguration was deliberately introduced to create a privilege escalation path
* 🚨 **Discover** — BloodHound identified Braya's indirect path to Server Admins through nested group membership
* 📋 **Document** — Finding documented as High-severity privilege creep
* 🔧 **Remediate** — Excessive nested group memberships removed
* ✅ **Validate** — SharpHound re-run confirms attack path no longer exists

> **Note:** BloodHound and SharpHound are legitimate security tools used by AD administrators and penetration testers to identify attack paths before attackers do. All testing was performed in an authorized, privately-owned lab environment (biksec.com domain).

---

## 🛠️ Technologies Used

* BloodHound (SpecterOps)
* SharpHound v2.13.0
* Neo4j 4.4.26 (graph database backend)
* Kali Linux (analysis machine)
* Windows Server 2022 (BIKSEC-DC01)
* Active Directory (biksec.com domain)
* SCP / SSH (data transfer)
* Cypher Query Language

---

## 🧪 Lab Environment

| Component | Value |
| --- | --- |
| Domain | biksec.com |
| Domain Controller | BIKSEC-DC01 (Windows Server 2022) |
| Analysis Machine | BIKSEC-LINUX (Kali Linux — 192.168.219.30) |
| SharpHound Version | v2.13.0 (Windows x86) |
| BloodHound | SpecterOps BloodHound (Kali package) |
| Graph Database | Neo4j 4.4.26 |
| Target User | Braya (Bimal Raya) — low-privileged domain user |

---

## 🌐 Lab Architecture

```
[BIKSEC-DC01 — Windows Server 2022]
  Active Directory — biksec.com
         │
         │  SharpHound.exe -c All
         │  Collects: Users, Groups, ACLs, Sessions, GPOs, Trusts
         ▼
  BloodHound ZIP → SCP transfer
         │
         ▼
[BIKSEC-LINUX — Kali Linux 192.168.219.30]
  Neo4j 4.4.26 (graph database)
  BloodHound UI (http://127.0.0.1:8080)
         │
         │  Import ZIP → Graph Analysis
         │  Cypher Queries
         ▼
  Attack Path Discovered:
  Braya → HelpDesk Team → IT Operations → Server Admins
         │
         ▼
  Remediation → SharpHound re-run → Path confirmed removed
```

---

## 🔬 Lab Phases

### Phase 1 — Tool Setup

- Downloaded BloodHound and SharpHound from SpecterOps GitHub
- Temporarily disabled Windows Defender real-time protection to allow offensive tool download (standard lab procedure)
- Ran SharpHound on Windows DC to collect AD data
- Set up SSH on Kali Linux for file transfer

### Phase 2 — Data Transfer

```bash
# On Kali — enable SSH
sudo apt-get install ssh
sudo systemctl enable ssh
sudo systemctl start ssh
```

```powershell
# On Windows DC — transfer SharpHound ZIP to Kali
scp "C:\Users\Administrator\Downloads\SharpHound_v2.13.0_windows_x86\20260712222836_BloodHound.zip" kali@192.168.219.30:/home/kali/Desktop/
```

Transfer result: `20260712222836_BloodHound.zip 100% 31KB 1.9MB/s`

### Phase 3 — BloodHound Setup

```bash
# Start Neo4j database
sudo neo4j console

# Start BloodHound
sudo bloodhound-start
# Web UI: http://127.0.0.1:8080
```

### Phase 4 — Initial AD Enumeration

**Query 1 — All Domain Admin Members:**
```cypher
MATCH p = (t:Group)<-[:MemberOf*1..]-(a)
WHERE (a:User or a:Computer) and t.objectid ENDS WITH '-512'
RETURN p
LIMIT 1000
```

**Query 2 — OU Structure:**
```cypher
MATCH p = (:Domain)-[:Contains*1..]->(:OU)
RETURN p
LIMIT 1000
```

---

## ⚠️ Phase 5 — Nested Group Misconfiguration

A nested group misconfiguration was deliberately configured to simulate a real-world privilege creep scenario:

**Groups created in biksec.com:**
- HelpDesk Team
- IT Operations
- Server Admins

**User created:** Bimal Raya (logon: `Braya`) — intended as a low-privileged HelpDesk user

**Misconfigured chain:**
```
Braya
  └─ MemberOf ─→ HelpDesk Team
                    └─ MemberOf ─→ IT Operations
                                      └─ MemberOf ─→ Server Admins
```

**Effect:** Braya inherits Server Admins permissions through nested membership — without any direct assignment.

---

## 🚨 Phase 6 — Attack Path Discovered

After re-running SharpHound and importing updated data into BloodHound:

### Finding: Excessive Privilege Through Nested Group Membership

| Property | Detail |
| --- | --- |
| **Finding** | Excessive Privilege Through Nested Group Membership (Privilege Creep) |
| **Severity** | 🔴 High |
| **Attack Path** | `Braya → HelpDesk Team → IT Operations → Server Admins` |
| **MITRE** | T1069 Permission Groups Discovery \| T1078 Valid Accounts \| T1484 Domain Policy Modification |

**Risk:** Braya is not directly assigned to Server Admins, but inherits all its permissions through nested group membership. A compromised HelpDesk account could escalate privileges to Server Admins without any explicit administrative assignment — a classic privilege creep scenario invisible in standard AD tools but immediately visible in BloodHound.

---

## 🔧 Phase 7 — Remediation

The excessive privilege path was remediated by removing unnecessary nested memberships:

| Action | Result |
| --- | --- |
| Removed HelpDesk Team from IT Operations | Chain broken at first hop |
| Removed IT Operations from Server Admins | Chain broken at second hop |
| Retained Braya in HelpDesk Team | Legitimate role access preserved |

**Result:** `Braya → HelpDesk Team` only — no path to Server Admins.

> In a real enterprise, this change would go through a change management process. BloodHound's "Shortest Paths to Domain Admins" and "Find All Paths from Domain Users to High Value Targets" queries are used to identify all similar nested group chains across the domain.

---

## ✅ Phase 8 — Validation

```powershell
# Re-run SharpHound after remediation
SharpHound.exe -c All
```

After importing the updated ZIP into BloodHound:

✅ **Braya's MemberOf shows HelpDesk Team only**
✅ **No path to Server Admins exists**
✅ **Privilege escalation path confirmed removed**

---

## 🎯 MITRE ATT&CK Techniques

| Technique | Name | Relevance |
| --- | --- | --- |
| T1069 | Permission Groups Discovery | BloodHound enumerates all group memberships and effective permissions |
| T1078 | Valid Accounts | A low-privileged account (Braya) gains elevated access through inheritance |
| T1484 | Domain Policy Modification | Nested group memberships effectively modify the privilege structure |

---

## 🎯 Skills Demonstrated

* Active Directory Enumeration (BloodHound / SharpHound)
* Graph-Based Attack Path Analysis
* Cypher Query Language (Neo4j)
* Privilege Escalation Path Identification
* Nested Group Misconfiguration Analysis
* Privilege Creep Detection
* SSH Configuration & SCP File Transfer
* Active Directory Group Management
* Principle of Least Privilege Application
* MITRE ATT&CK Technique Mapping
* Security Finding Documentation
* Remediation & Validation Cycle

---

## 🎯 Key Takeaway

> This lab demonstrates end-to-end Active Directory security assessment using BloodHound and SharpHound — covering the full cycle of enumeration, attack path discovery, finding documentation, remediation, and validation. A nested group misconfiguration created a privilege escalation path that was invisible in standard AD tools but immediately apparent in BloodHound's graph analysis. The same assess-document-remediate-validate cycle is used by penetration testers and AD security analysts performing enterprise Active Directory assessments.

---

## 🔗 Related Projects

> Part of the **Bikash Security Lab** series:
> * [System Hardening Lab — Linux, Windows Server & AD](https://github.com/Bikash-Raya/system-hardening-lab-linux-windows-active-directory)
> * [Nessus Vulnerability Management Lab](https://github.com/Bikash-Raya/Nessus-Vulnerability-Management-Lab)
> * [Microsoft Sentinel & Defender XDR — SOC IR Lab](https://github.com/Bikash-Raya/Sentinel-Defender-XDR-SOC-Incident-Response-lab)

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
