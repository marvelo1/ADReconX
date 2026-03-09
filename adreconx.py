import os
import sys
import argparse
from colorama import init

# Initialize colorama for Windows
init(autoreset=True)

from core.logger import setup_logger

logger = setup_logger()

BANNER = """
\033[31m    ___    ____  ____                           _  __
   /   |  / __ \\/ __ \\___  _________  ____     | |/ /
  / /| | / / / / /_/ / _ \\/ ___/ __ \\/ __ \\    |   / 
 / ___ |/ /_/ / _, _/  __/ /__/ /_/ / / / /   /   |  
/_/  |_/_____/_/ |_|\\___/\\___/\\____/_/ /_/   /_/|_|v0.1\033[0m
                                          
\033[36mProfessional Active Directory Security Scanner\033[0m
"""

def print_banner():
    print(BANNER)

def main():
    parser = argparse.ArgumentParser(description="ADReconX - Active Directory Security Scanner", 
                                     formatter_class=argparse.RawTextHelpFormatter)
    
    # Global options
    parser.add_argument('-d', '--domain', help='Target domain (e.g., example.local)')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-H', '--hashes', help='NTLM hashes, format is LMHASH:NTHASH')
    parser.add_argument('--dc-ip', help='IP Address of the Domain Controller')
    parser.add_argument('-w', '--workspace', help='Workspace name for evidence management', default='default')
    
    # Operation modes
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--auto', action='store_true', help='Automatic mode: Run full enumeration and safe exploitation chain')
    mode_group.add_argument('--semi-auto', action='store_true', help='Semi-auto mode: Prompt before exploiting vulnerabilities')
    mode_group.add_argument('--manual', action='store_true', help='Manual mode: Drop into an interactive interactive console')
    
    # Specific Modules (if not running auto)
    module_group = parser.add_argument_group('Modules')
    module_group.add_argument('--sweep', help='CIDR network range to sweep for DCs before running', metavar='CIDR')
    module_group.add_argument('--enum', action='store_true', help='Run comprehensive AD enumeration (DNS, LDAP, SMB)')
    module_group.add_argument('--bloodhound', action='store_true', help='Collect and analyze BloodHound data')
    module_group.add_argument('--spray', help='Perform password spraying using the specified password file', metavar='PASS_FILE')
    module_group.add_argument('--adcs', action='store_true', help='Detect ADCS and enumerate templates')

    args = parser.parse_args()

    print_banner()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    # Initialize workspace based on domain or provided argument
    workspace_name = args.workspace
    if workspace_name == 'default' and args.domain:
        workspace_name = args.domain.replace('.', '_')
        
    workspace_dir = os.path.join(os.getcwd(), 'workspaces', workspace_name)
    if not os.path.exists(workspace_dir):
        os.makedirs(workspace_dir)
        logger.info(f"Created workspace: {workspace_dir}")
    else:
        logger.info(f"Using workspace: {workspace_dir}")

    # Mode logic
    if args.manual:
        logger.info("Starting interactive manual mode...")
        from core.console import start_interactive_console
        start_interactive_console(args)
    elif args.auto or args.semi_auto:
        mode_name = "Fully Automatic" if args.auto else "Semi-Automatic (Prompts Enabled)"
        logger.info(f"Starting {mode_name} runtime...")
        from core.prompts import ask_permission
        
        # Determine if we should ask for permission based on the mode
        def should_run(module_name, risk_level="Low"):
            if args.auto:
                return True
            return ask_permission(module_name, risk_level)

        # -------------------------------------------------------------------
        # THE AUTO-EXPLOITATION CHAIN (Phase 1: Recon & Enum)
        # -------------------------------------------------------------------
        
        # 0. High Speed Network Sweeping
        if args.sweep:
            if should_run(f"High-Speed Network Sweep ({args.sweep})", risk_level="Low"):
                from modules.enum.sweep import run_network_sweep
                live_hosts, dc_candidates = run_network_sweep(args.sweep, args.workspace)
                if not args.dc_ip and dc_candidates:
                     args.dc_ip = dc_candidates[0]
                     logger.info(f"[+] Auto-configured DC_IP to {args.dc_ip} from sweep results.")
                     
        if not args.dc_ip:
             logger.error("[-] No DC_IP provided or found via sweep. Aborting auto-chain!")
             sys.exit(1)

        # 1. DNS Enumeration (Low Risk)
        if should_run("DNS Enumeration (SRV & Zone Transfers)", risk_level="Low"):
            from modules.enum.dns_enum import run_dns_enum
            run_dns_enum(args.dc_ip, args.domain)

        # 2. LDAP Enumeration (Low Risk)
        if should_run("LDAP Enumeration & Mapping", risk_level="Low"):
            from modules.enum.ldap_enum import run_ldap_enum
            args.domain = run_ldap_enum(args.dc_ip, args.domain, args.username, args.password, args.hashes, args.workspace)

        # 3. SMB Enumeration & GPP Spidering (Low Risk)
        if should_run("SMB Share Crawling & GPP Spidering", risk_level="Low"):
            from modules.enum.smb_enum import run_smb_enum
            run_smb_enum(args.dc_ip, args.username, args.password, args.hashes, args.workspace)

        # 3.1 MSSQL Enumeration & Auto-RCE (Med Risk)
        if should_run("MSSQL Auto-Login & xp_cmdshell Detection", risk_level="Medium"):
            from modules.enum.mssql_enum import run_mssql_enum
            run_mssql_enum(args.dc_ip, args.domain, args.username, args.password, args.hashes)

        # -------------------------------------------------------------------
        # THE AUTO-EXPLOITATION CHAIN (Phase 2: Privilege Escalation)
        # -------------------------------------------------------------------

        # 4. AS-REP Roasting (Low Risk)
        if should_run("AS-REP Roasting (Offline Cracking)", risk_level="Low"):
            from modules.exploit.kerberos import run_asreproast
            run_asreproast(args.dc_ip, args.domain, args.username, args.password, args.hashes)

        # 5. Kerberoasting (Med Risk - Logs TGS request)
        if should_run("Kerberoasting (Extract Service Ticket Hashes)", risk_level="Medium"):
            from modules.exploit.kerberos import run_kerberoast
            run_kerberoast(args.dc_ip, args.domain, args.username, args.password, args.hashes)

        # 6. ADCS Detection & Template Checking (Low Risk)
        if should_run("ADCS ESC1-13 Vulnerability Detection", risk_level="Low"):
            from modules.exploit.adcs import check_adcs
            check_adcs(args.dc_ip, args.domain, args.username, args.password, args.hashes, args.workspace)

        # -------------------------------------------------------------------
        # THE AUTO-EXPLOITATION CHAIN (Phase 3: Deep Collection & Harvesting)
        # -------------------------------------------------------------------

        # 7. BloodHound Collection (High Noise Level)
        if should_run("BloodHound AD Topology Collection", risk_level="Medium (Noisy)"):
            from modules.bloodhound.collector import run_bloodhound
            run_bloodhound(args.dc_ip, args.domain, args.username, args.password, args.hashes, args.workspace)
            
            # Immediately run pathfinder if Bloodhound succeeds
            if should_run("Beta: Algorithmic Attack Path Selection", risk_level="Low"):
                from modules.bloodhound.pathfinder import execute_attack_path
                execute_attack_path(args.dc_ip, args.domain, args.workspace)

        # 8. Safe Password Spraying (High Risk)
        if args.spray or (not args.auto and should_run("Safe Password Spraying (Single Password Sweep)", risk_level="High")):
            from modules.post.password_spray import run_password_spray
            run_password_spray(args.dc_ip, args.domain, args.username, args.password, args.hashes, args.workspace, pass_list=args.spray)

        # 9. Credential Harvesting / DCSync (High Risk)
        if should_run("Credential Harvesting (DCSync / NTDS / LSA)", risk_level="High"):
            from modules.post.cred_harvest import run_credential_harvesting
            run_credential_harvesting(args.dc_ip, args.domain, args.username, args.password, args.hashes, args.workspace)

        # -------------------------------------------------------------------
        # THE AUTO-EXPLOITATION CHAIN (Phase 4: Reporting)
        # -------------------------------------------------------------------

        # 9. Automated Markdown Reporting (No Risk)
        if should_run("Report Generation (Markdown & MITRE ATT&CK Mapping)", risk_level="None"):
            from modules.report.generator import generate_report
            generate_report(args.domain, args.workspace)

        logger.info(f"\n[+] Chain Complete. Data exported to Workspace: {args.workspace}")
    else:
        # Run specific modules
        if args.enum:
            logger.info("Running general AD enumeration...")
            from modules.enum.ldap_enum import run_ldap_enum
            args.domain = run_ldap_enum(args.dc_ip, args.domain, args.username, args.password, args.hashes)
        if args.bloodhound:
            logger.info("Starting BloodHound collection...")
        if args.spray:
            logger.info(f"Starting password spraying with {args.spray}...")
        if args.adcs:
            logger.info("Enumerating ADCS infrastructure...")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[31m[!] Exiting ADReconX...\033[0m")
        sys.exit(0)
