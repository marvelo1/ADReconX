# ADReconX

> **Professional Active Directory Security Scanner & Auto-Exploitation Framework**

ADReconX is a comprehensive, modular framework designed for both automated and interactive red team operations against Active Directory environments. It natively integrates industry-standard tools (Impacket, BloodHound, Certipy) into a sleek pipeline capable of safe enumeration, deep credential harvesting, and automatic mitigation reporting mapped to the MITRE ATT&CK framework.

---

## 🚀 Current Development State (v0.1.0)

We have successfully built the core engine and populated all primary functional modules. The tool currently supports three primary execution modes:

### 1. Execution Modes
*   **Fully Automated (`--auto`)**: Fires the entire exploitation chain sequentially (Recon -> Exploitation -> Post-Exploitation -> Reporting) with zero interaction required.
*   **Semi-Automated (`--semi-auto`)**: The "Safe Mode". Pauses execution and prompts the user for confirmation `[y/N]` before executing noisy or high-risk modules (like DCSync or Password Spraying).
*   **Interactive Console (`--manual`)**: A Cobalt Strike / Metasploit-style interactive loop `ADReconX[example.local] >` allowing granular control over variables, authentication, and manual execution of individual modules.

### 2. Built & Tested Modules Capability List:
*   ✅ **Reconnaissance & Enumeration**:
    *   **High-Speed Sweeping**: Multi-threaded subnet sweeping for Active Directory services.
    *   **Nmap Integration**: Automatic detailed service banner and vulnerability extraction on discovered live hosts.
    *   **DNS**: SRV record extraction and attempted Zone Transfers.
    *   **LDAP**: Authenticated and Anonymous binding, user extraction, Admin identification.
    *   **Advanced Data Extraction**: Identifies Domain Password & Lockout Policies, all Computer Objects and their Operating Systems, and attempts extraction of cleartext LAPS passwords.
    *   **Deep Filtering**: Extracts active High-Privileged Admins, accounts with `Password Never Expires`, Disabled Accounts, and identifies `Kerberoastable` and `AS-REP Roasting` vulnerable accounts natively without Impacket.
    *   **Automated Attack Vector Detection**: Dynamically parses LDAP to find accounts vulnerable to:
        *   Resource-Based Constrained Delegation (RBCD)
        *   Shadow Credentials (PKINIT Abuse)
        *   Unconstrained & Constrained Delegation
        *   Readable Group Managed Service Account (gMSA) Passwords
        *   MachineAccountQuota (>0) Validation
        *   AdminSDHolder Existence
        *   Fine-Grained Password Policies (PSOs)
        *   \033[36m*All findings, including the exact extracted vulnerable accounts and computers, are logged to `workspaces/{workspace_name}/ldap_vulns.txt` for reporting*\033[0m
    *   **SMB**: Share crawling, open-access checks, and searching for GPP passwords/secrets.
    *   **MSSQL**: Target specific databases, automatically attempts Windows and SQL authentication, enumerates version/sysadmin privileges, and automatically executes `xp_cmdshell` RCE if permissions allow.
*   ✅ **Credential Exploitation (Kerberos)**:
    *   **AS-REP Roasting**: Hunting for users with DONT_REQ_PREAUTH set.
    *   **Kerberoasting**: Requesting TGS tickets for SPN accounts for offline cracking.
*   ✅ **Active Directory Certificate Services (ADCS)**:
    *   Native integration with `certipy-ad` to scan the domain for vulnerable ESC1-ESC13 certificate templates.
*   ✅ **Advanced Privilege Escalation**:
    *   **ADCS Auto-Exploitation**: Automatically extracts the ESC1 template and CA name, requests an Administrator `.pfx` certificate, and executes PKINIT to retrieve the Domain Admin NTLM hash.
    *   **RBCD**: Automates Resource-Based Constrained Delegation exploitation attacks.
    *   **Algorithmic Attack Path Selection**: Reads completed BloodHound graphs, calculates Breadth-First-Search paths from compromised users to Domain Admins, and outlines the exploit chain needed.
*   ✅ **Post-Exploitation & Harvesting**:
    *   **BloodHound Collection**: Fully automated AD topology ingestion via `bloodhound-python`.
    *   **DCSync / NTDS Extraction**: Precise execution of `secretsdump` targeting the DC to harvest hashes.
    *   **🔥 Smart Safe Password Spraying**: Advanced module that queries the Domain Lockout Policy *before* spraying. Parses BloodHound outputs or giant external wordlists, automatically throttling to 1-password attempts if a tight lockout policy (e.g., 3 attempts) is detected.
    *   **LPE & AMSI Bypass**: Automatically executes a Base64-encoded PowerShell payload over WMI to bypass AMSI protections and natively memory-inject instances of `PowerUp` or `winPEAS` without touching disk or dropping dependencies.
*   ✅ **Professional Reporting**:
    *   Automated parsing of all workspace logs. Generates a beautifully formatted **Markdown** and professional **PDF** report documenting vulnerabilities, affected accounts, and mapping to **MITRE ATT&CK** TTPs.

---

## 📦 Installation

ADReconX requires Python 3 and runs best within a dedicated virtual environment. It also relies natively on `nmap` for the high-speed network scanning module.

### 1. Install System Dependencies (APT)
```bash
sudo apt-get update
sudo apt-get install -y nmap smbclient python3-venv python3-pip python3-dev libssl-dev libffi-dev build-essential
```

### 2. Environment Setup
```bash
# Clone the repository
# git clone https://github.com/marvelo1/ADReconX.git
cd ADReconX

# Create and activate a Python virtual environment
python3 -m venv adreconx-env
source adreconx-env/bin/activate

# Install all Python dependencies
pip install -r requirements.txt
```

---

## 🛠️ Usage

### Quick Start (Auto Mode)
Run the entire chain against a subnet, automatically discovering the DC and executing all modules (Warning: very loud):
```bash
python3 adreconx.py --auto --sweep 192.168.1.0/24 -d example.local -u pentest -p "Welcome1!"
```

### Interactive Console Mode
Drop into the interactive shell to run specific, targeted attacks manually.

Start the console:
```bash
python3 adreconx.py --manual
```

#### Example Testing Workflow (Copy/Paste these in the console):
```text
# 0. Sweep the network to find the Domain Controller automatically
ADReconX[Unset] > run sweep 192.168.1.0/24

# 1. Prepare your workspace and authentication
ADReconX[Unset] > workspace client_test
ADReconX[Unset] > set DC_IP 192.168.1.100
ADReconX[Unset] > set DOMAIN example.local
ADReconX[Unset] > auth pentest Welcome1!

# 2. Verify your settings are correct
ADReconX[example.local] > options

# 3. Test Basic Enumeration (DNS, LDAP, SMB)
ADReconX[example.local] > run enum

# 3.1 Test MSSQL (Targeting the DC or a specific IP)
ADReconX[example.local] > run mssql 192.168.1.100

# 4. Test Kerberos Exploitation
ADReconX[example.local] > run asreproast
ADReconX[example.local] > run kerberoast

# 5. Test Advanced Modules (ADCS & BloodHound)
ADReconX[example.local] > run adcs
ADReconX[example.local] > run bloodhound

# 6. Test the Safe Password Sprayer (using local userlist.txt if available)
ADReconX[example.local] > run spray Spring2026!

# 7. Perform LPE Checks & AMSI Bypass (Memory Inject PowerUp)
ADReconX[example.local] > run lpe powerup

# 8. Generate the Final Markdown Report for this Workspace
ADReconX[example.local] > run report
```

---

## 🗺️ Roadmap / Pending Features

1.  **Fully Developed Bloodhound Graph API**: Build a custom NetworkX/Py2Neo interface to programmatically calculate Breadth-First-Search paths natively from the offline ZIP file and route them to exploit handlers.
2.  **BloodHound API Integration**: Allow users to configure BloodHound CE / Enterprise API credentials natively to automatically push collection data straight into their live instance via REST API instead of dropping zip files.
3.  **BloodHound Live Attack Path Queries**: Connect to BloodHound's live Neo4j database using Cypher queries to mathematically calculate and log the exact shortest path from the compromised user to Domain Admin.
4.  **Automated RBCD / Constrained Delegation Exploitation**: Add a module that automatically consumes the LDAP `MachineAccountQuota` and Delegation data to spawn a rogue computer object and forge a Service Ticket (`impacket-getST`) gaining full Administrator access effortlessly.
5.  **Advanced Persistence (Golden/Silver Tickets)**: Automate `ticketer.py` workflows to use the extracted `krbtgt` or computer hashes to generate 10-year validity Golden/Silver tickets automatically for immediate Pass-The-Ticket deployment.
