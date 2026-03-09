import os
import glob
import glob
import glob
from datetime import datetime
from markdown_pdf import MarkdownPdf, Section
from core.logger import setup_logger

logger = setup_logger()

def generate_report(domain: str, workspace: str) -> bool:
    """
    Parses all output files in the workspace and generates a comprehensive Markdown report
    mapping findings to MITRE ATT&CK techniques.
    """
    logger.info("[*] Compiling workspace artifacts into Executive Summary Report...")
    workspace_dir = os.path.join(os.getcwd(), 'workspaces', workspace)
    
    if not os.path.exists(workspace_dir):
        logger.error(f"[-] Workspace {workspace_dir} not found. Cannot generate report.")
        return False
        
    report_file = os.path.join(workspace_dir, f"ADReconX_Report_{workspace}.md")
    
    # Initialize Report Content
    lines = []
    lines.append(f"# ADReconX Security Assessment Report: {domain.upper()}")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Target Domain:** `{domain}`\n")
    
    lines.append("## Executive Summary")
    lines.append("This report outlines the discovered vulnerabilities and mapped MITRE ATT&CK techniques identified during the automated ADReconX enumeration and exploitation chain.\n")
    
    vulns_found = False
    lines.append("## Identified Vulnerabilities & Artifacts\n")
    
    # 1. AS-REP Roasting
    asrep_file = os.path.join(workspace_dir, "asreproast.txt")
    if os.path.exists(asrep_file) and os.path.getsize(asrep_file) > 0:
        vulns_found = True
        lines.append("### 🔴 AS-REP Roasting (T1558.004)")
        lines.append("> Users without Kerberos Pre-Authentication were identified. Their AS-REP hashes were extracted and can be cracked offline.")
        lines.append(f"**Artifact:** `{asrep_file}`")
        with open(asrep_file, "r") as f:
            lines.append("```text")
            lines.append(f.read().strip())
            lines.append("```\n")
            
    # 2. Kerberoasting
    kerb_file = os.path.join(workspace_dir, "kerberoast.txt")
    if os.path.exists(kerb_file) and os.path.getsize(kerb_file) > 0:
        vulns_found = True
        lines.append("### 🔴 Kerberoasting (T1558.003)")
        lines.append("> Service Principal Names (SPNs) were identified. Their Ticket Granting Service (TGS) tickets were extracted and can be cracked offline.")
        lines.append(f"**Artifact:** `{kerb_file}`")
        with open(kerb_file, "r") as f:
            lines.append("```text")
            lines.append(f.read().strip())
            lines.append("```\n")
            
    # 3. GPP Passwords
    gpp_file = os.path.join(workspace_dir, "gpp_passwords.txt")
    if os.path.exists(gpp_file) and os.path.getsize(gpp_file) > 0:
        vulns_found = True
        lines.append("### 🔴 Group Policy Preferences (GPP) Passwords (T1552.006)")
        lines.append("> Legacy Groups.xml files containing AES-encrypted `cpassword` fields were discovered in SYSVOL/NETLOGON. The passwords were automatically decrypted.")
        lines.append(f"**Artifact:** `{gpp_file}`")
        with open(gpp_file, "r") as f:
            lines.append("```text")
            lines.append(f.read().strip())
            lines.append("```\n")

    # 4. DCSync / NTDS Extraction
    dcsync_file = os.path.join(workspace_dir, "dcsync_log.txt")
    if os.path.exists(dcsync_file):
        with open(dcsync_file, "r") as f:
            content = f.read()
            if "rpc_s_access_denied" not in content.lower() and "failed" not in content.lower() and len(content) > 50:
                vulns_found = True
                lines.append("### ☠️ DCSync / Credentials Harvested (T1003.006)")
                lines.append("> The provided credentials possessed `DS-Replication-Get-Changes` privileges. The Active Directory database (NTDS.dit) was successfully replicated and hashes were extracted.")
                lines.append(f"**Artifacts Available:** `dcsync_dump.ntds`, `dcsync_dump.sam`\n")

    # 5. ADCS Misconfigurations (Certipy)
    cert_txt_files = glob.glob(os.path.join(workspace_dir, "*_Certipy.txt"))
    valid_certs = []
    
    for cert in cert_txt_files:
        with open(cert, "r") as f:
            content = f.read()
            if "Vulnerable" in content or "\n  [0]" in content:
                valid_certs.append(cert)
                
    if valid_certs:
        vulns_found = True
        lines.append("### 🔴 ADCS Exploitable Templates (T1649)")
        lines.append("> Certipy identified Active Directory Certificate Services infrastructure with vulnerable templates allowing domain escalation.")
        for cert in valid_certs:
            lines.append(f"**Artifact:** `{cert}`")
        lines.append("\n")

    # 6. BloodHound Topology
    bh_zips = glob.glob(os.path.join(workspace_dir, "*_bloodhound.zip"))
    if bh_zips:
        vulns_found = True
        lines.append("### 🟡 Active Directory Graph Topology mapped (T1087)")
        lines.append("> BloodHound was successfully executed. The domain layout, Active Directory users, groups, ACLs, and trusts were collected and zipped for review.")
        lines.append(f"**Artifact:** `{bh_zips[-1]}`\n")
        
    if not vulns_found:
        lines.append("No critical vulnerabilities (AS-REP, Kerberoasting, GPP, or DCSync) were successfully discovered with the provided access level.\n")

    # Write the report
    try:
        with open(report_file, "w", encoding='utf-8') as f:
            f.write("\n".join(lines))
        logger.info(f"[+] Markdown Report successfully generated at: {report_file}")
        
        # --- PDF Generation Phase ---
        logger.info("[*] Compiling Markdown into Professional PDF Deliverable...")
        pdf_file = os.path.join(workspace_dir, f"ADReconX_Report_{workspace}.pdf")
        
        pdf = MarkdownPdf(toc_level=2)
        # Convert our raw lines string back to a single text
        md_text = "\n".join(lines)
        pdf.add_section(Section(md_text))
        
        # Save output
        pdf.save(pdf_file)
        logger.info(f"[+] \033[32mSuccess! Executive PDF generated at: {pdf_file}\033[0m")
             
        return True
    except Exception as e:
        logger.error(f"[-] Failed to write report file: {e}")
        return False
