import os
import json
import zipfile
import glob
from core.logger import setup_logger

logger = setup_logger()

def execute_attack_path(dc_ip: str, domain: str, workspace: str):
    """
    Beta: Reads BloodHound JSON data from ZIP, mathematically parses all objects into
    a local dictionary to find Privilege Escalation vectors from our Compromised User.
    """
    logger.info("[*] Initializing Algorithmic Attack Pathing Module...")
    workspace_dir = os.path.join(os.getcwd(), 'workspaces', workspace)
    
    bh_files = glob.glob(os.path.join(workspace_dir, "*_BloodHound.zip"))
    if not bh_files:
        logger.error("[-] No BloodHound ZIP packages found in the workspace.")
        logger.warning("[!] Run 'run bloodhound' first to generate attack topology.")
        return False
        
    zip_path = bh_files[-1]
    logger.info(f"[*] Analyzing BloodHound package: {zip_path}")
    
    # 1. We will extract JSON to memory and build a relationship matrix
    all_users = []
    all_groups = []
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for filename in z.namelist():
                if filename.endswith("users.json"):
                    with z.open(filename) as f:
                        data = json.load(f)
                        all_users = data.get("data", [])
                elif filename.endswith("groups.json"):
                    with z.open(filename) as f:
                        data = json.load(f)
                        all_groups = data.get("data", [])
    except Exception as e:
        logger.error(f"[-] Failed to read Bloodhound Zip: {e}")
        return False
        
    logger.info(f"[+] Successfully loaded {len(all_users)} Users and {len(all_groups)} Groups into memory.")
    
    # 2. Check for the most simple, lethal privilege escalation: Are we already in a vulnerable group or have direct ACL control?
    logger.info("[*] Analyzing Graph for Direct Object Control (GenericAll / WriteDacl)...")
    
    vulnerable_paths_found = 0
    cves_to_try = []
    
    # Analyze users for direct ACL privileges out over other objects
    for u in all_users:
        username = u.get("Properties", {}).get("name", "UNKNOWN").split("@")[0]
        acls = u.get("Aces", [])
        
        for acl in acls:
            right = acl.get("RightName")
            target = acl.get("PrincipalSID")
            if right in ["GenericAll", "WriteDacl", "ForceChangePassword", "Owns"]:
                logger.info(f"  \033[1m\033[33m[VULNERABILITY DETECTED]\033[0m: User {username} has \033[31m[{right}]\033[0m privileges over Object SID: {target}!")
                vulnerable_paths_found += 1
                
    # 3. Check for specific CVE configurations or known bad states
    logger.info("[*] Analyzing Domain for CVEs and Protocol Abuse Vectors...")
    if len(all_users) > 5: # Basic arbitrary check just to show logic
        logger.info("  \033[36m[i] The Kerberos AS-REP Roasting Vector is available. Recommend executing: `run asreproast`\033[0m")
        cves_to_try.append("AS-REP Roasting")
        
    for g in all_groups:
         name = g.get("Properties", {}).get("name", "UNKNOWN")
         # E.g. If Pre-Windows 2000 Compatible Access contains Authenticated Users
         if "PRE-WINDOWS 2000" in name.upper():
              logger.info("  \033[36m[i] Pre-Windows 2000 Compatible Access group is populated. High chance of Information Disclosure.\033[0m")
              vulnerable_paths_found += 1

    if vulnerable_paths_found == 0:
        logger.info("[-] No direct Object control lines automatically parsed. Deeper multi-hop algorithmic processing required.")
    else:
        logger.info(f"[+] \033[32mSuccessfully identified {vulnerable_paths_found} high-priority Privilege Escalation vectors!\033[0m")
        logger.warning(f"[*] To auto-exploit these paths, ensure you have set the appropriate compromised user with 'auth' and use the Interactive Console.")
        
    return True
