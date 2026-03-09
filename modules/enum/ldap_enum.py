import os
import ldap3
from core.logger import setup_logger
from rich.table import Table
from rich.console import Console

logger = setup_logger()
console = Console()

class LDAPScanner:
    def __init__(self, domain_controller, domain, username=None, password=None, ntlm_hash=None, workspace='default'):
        self.domain_controller = domain_controller
        self.domain = domain
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.workspace = workspace
        self.log_file = os.path.join(os.getcwd(), 'workspaces', self.workspace, 'ldap_vulns.txt')
        
        # Build base DN
        if self.domain:
            self.base_dn = ','.join([f"DC={part}" for part in self.domain.split('.')])
        else:
            self.base_dn = None
            
        self.conn = None

    def connect(self):
        """Attempts to connect and bind to the LDAP server."""
        try:
            logger.info(f"[*] Attempting LDAP connection to {self.domain_controller}...")
            server = ldap3.Server(self.domain_controller, get_info=ldap3.ALL)

            # 1. Try Authenticated Bind
            if self.username and (self.password or self.ntlm_hash):
                auth_user = f"{self.domain}\\{self.username}" if self.domain else f"{self.domain_controller}\\{self.username}"
                auth_password = self.password if self.password else self.ntlm_hash
                logger.info(f"[*] Attempting authenticated bind as: {auth_user}")
                
                self.conn = ldap3.Connection(server, user=auth_user, password=auth_password, authentication=ldap3.NTLM)
                    
                if self.conn.bind():
                    logger.info("[+] \033[32mAuthenticated bind successful!\033[0m")
                    if not self.base_dn and server.info:
                        self.base_dn = server.info.other.get('defaultNamingContext', [None])[0]
                    if not self.domain and self.base_dn:
                        parts = [p.split('=')[1] for p in self.base_dn.split(',') if p.upper().startswith('DC=')]
                        self.domain = '.'.join(parts)
                        if self.domain:
                            logger.info(f"[+] Auto-discovered domain: {self.domain}")
                    return True
                else:
                    logger.error("[-] Authenticated bind failed. Verify credentials.")
                    return False

            # 2. Try Anonymous Bind if no creds
            logger.info("[-] No credentials provided. Attempting Anonymous Bind...")
            self.conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS)
            if self.conn.bind():
                logger.info("[+] Anonymous bind successful! We can query LDAP.")
                if not self.base_dn and server.info:
                    self.base_dn = server.info.other.get('defaultNamingContext', [None])[0]
                if not self.domain and self.base_dn:
                    parts = [p.split('=')[1] for p in self.base_dn.split(',') if p.upper().startswith('DC=')]
                    self.domain = '.'.join(parts)
                return True
            else:
                logger.error("[-] Anonymous bind disabled or failed.")
                return False

        except Exception as e:
            logger.error(f"[-] LDAP Connection Exception: {str(e)}")
            return False

    def get_domain_policy(self):
        """Extracts Domain Password and Lockout Policies."""
        logger.info(f"[*] Extracting Domain Password Policy...")
        search_filter = '(objectClass=domainDNS)'
        attributes = ['minPwdLength', 'pwdHistoryLength', 'lockoutThreshold', 'lockoutDuration']
        self.conn.search(self.base_dn, search_filter, attributes=attributes)
        
        if self.conn.entries:
            entry = self.conn.entries[0]
            print("\n\033[1m\033[36m==== Domain Security Policy ====\033[0m")
            print(f"  Minimum Password Length :  {getattr(entry, 'minPwdLength', 'Unknown')}")
            print(f"  Password History Count  :  {getattr(entry, 'pwdHistoryLength', 'Unknown')}")
            print(f"  Account Lockout Threshold: {getattr(entry, 'lockoutThreshold', 'Unknown')} attempts")
            print(f"  Account Lockout Duration : {getattr(entry, 'lockoutDuration', 'Unknown')}")
    
    def enumerate_users(self):
        """Enumerates domain users."""
        logger.info(f"[*] Querying users in: {self.base_dn}")
        
        search_filter = '(objectCategory=person)'
        attributes = ldap3.ALL_ATTRIBUTES
        self.conn.search(self.base_dn, search_filter, attributes=attributes)
        
        entries = self.conn.entries
        logger.info(f"[+] Found {len(entries)} user objects.")

        table = Table(title="Domain Users (Preview)", show_header=True, header_style="bold magenta")
        table.add_column("Username", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Admin", justify="center")

        count = 0
        kerberoastable = []
        asreproastable = []

        for entry in entries:
            try:
                username = ""
                if 'sAMAccountName' in entry and entry.sAMAccountName.value:
                    username = str(entry.sAMAccountName.value)
                else:
                    continue
                    
                desc = ""
                if 'description' in entry and entry.description.value:
                    desc = str(entry.description.value)
                    
                uac = 0
                if 'userAccountControl' in entry and entry.userAccountControl.value:
                    uac = int(entry.userAccountControl.value)
                
                # Check for Administrators
                is_admin = ""
                if 'memberOf' in entry and entry.memberOf.value:
                    groups = entry.memberOf.value if isinstance(entry.memberOf.value, list) else [entry.memberOf.value]
                    if any('admin' in str(group).lower() for group in groups):
                        is_admin = "\033[31mYES\033[0m"

                # Check for Kerberoastable Users (Has SPN + isn't a computer)
                if 'servicePrincipalName' in entry and entry.servicePrincipalName.value and not username.endswith('$'):
                    kerberoastable.append(username)
                
                # Check for AS-REP Roasteable Users (DONT_REQ_PREAUTH flag is 0x400000 -> 4194304)
                if uac & 4194304:
                    asreproastable.append(username)

                table.add_row(username, desc[:50] + ('...' if len(desc)>50 else ''), is_admin)
                count += 1
                if count >= 15: 
                    break
            except Exception as e:
                # logger.error(f"Error parsing user: {e}")
                continue

        if len(entries) > 0:
            console.print(table)
            if len(entries) > 15:
                logger.info(f"... and {len(entries)-15} more users (data saved to workspace).")
                
        # Print Vulnerabilities Discovered
        if asreproastable or kerberoastable:
            print("\n\033[1m\033[31m[!] HIGH-RISK Kerberos Vulnerabilities Detected via LDAP:\033[0m")
            if asreproastable:
                print(f"  --> \033[31mAS-REP Roasting Vulnerable Users:\033[0m {', '.join(asreproastable)}")
            if kerberoastable:
                print(f"  --> \033[31mKerberoastable Service Accounts:\033[0m {', '.join(kerberoastable)}")

    def enumerate_computers(self):
        """Enumerates computer objects to find servers and workstations."""
        logger.info(f"[*] Querying computers in: {self.base_dn}")
        
        search_filter = '(objectCategory=computer)'
        attributes = ldap3.ALL_ATTRIBUTES
        self.conn.search(self.base_dn, search_filter, attributes=attributes)
        
        entries = self.conn.entries
        logger.info(f"[+] Found {len(entries)} computer objects.")
        
        table = Table(title="Domain Computers (Preview)", show_header=True, header_style="bold yellow")
        table.add_column("Hostname", style="cyan")
        table.add_column("Operating System", style="blue")
        table.add_column("LAPS Password", style="red")
        
        laps_found = False
        count = 0
        for entry in entries:
            try:
                hostname = ""
                # Computers usually have dNSHostName, fallback to sAMAccountName
                if 'dNSHostName' in entry and entry.dNSHostName.value:
                    hostname = str(entry.dNSHostName.value)
                elif 'sAMAccountName' in entry and entry.sAMAccountName.value:
                    hostname = str(entry.sAMAccountName.value)
                    
                os_name = "Unknown"
                if 'operatingSystem' in entry and entry.operatingSystem.value:
                     os_name = str(entry.operatingSystem.value)
                
                # Check for plaintext LAPS passwords!
                laps_pwd = ""
                if 'ms-Mcs-AdmPwd' in entry and entry['ms-Mcs-AdmPwd'].value:
                     laps_pwd = str(entry['ms-Mcs-AdmPwd'].value)
                     laps_found = True
                     
                table.add_row(str(hostname), str(os_name), laps_pwd)
                count += 1
                if count >= 10:
                    break
            except Exception as e:
                continue
                
        if len(entries) > 0:
             console.print(table)
             
        if laps_found:
             logger.warning("\033[1m\033[31m[!!!] CRITICAL: Your account has privileges to read Plaintext LAPS Passwords directly from LDAP!\033[0m")

    def enumerate_advanced_filters(self):
        """Runs advanced precise LDAP queries to find specific high-value objects."""
        logger.info("[*] Running Advanced LDAP Detail Filters...")
        
        # 1. Active Domain/Enterprise Admins
        search_filter = '(&(objectClass=user)(objectCategory=Person)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        self.conn.search(self.base_dn, search_filter, attributes=['sAMAccountName'])
        admins = [str(e.sAMAccountName.value) for e in self.conn.entries if 'sAMAccountName' in e and e.sAMAccountName.value]
        
        # 2. Users with 'Password Never Expires'
        search_filter = '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        self.conn.search(self.base_dn, search_filter, attributes=['sAMAccountName'])
        no_expire = [str(e.sAMAccountName.value) for e in self.conn.entries if 'sAMAccountName' in e and e.sAMAccountName.value]
        
        # 3. Disabled Accounts
        search_filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'
        self.conn.search(self.base_dn, search_filter, attributes=['sAMAccountName'])
        disabled = [str(e.sAMAccountName.value) for e in self.conn.entries if 'sAMAccountName' in e and e.sAMAccountName.value]

        print("\n\033[1m\033[36m==== Detailed Active Directory Insights ====\033[0m")
        if admins:
            print(f"  \033[31m[!] High-Privileged Admins (Active):\033[0m {', '.join(admins)}")
        else:
            print(f"  \033[31m[!] High-Privileged Admins (Active):\033[0m None found")
            
        if no_expire:
            print(f"  \033[33m[i] Passwords Never Expire (Active):\033[0m {', '.join(no_expire)}")
        else:
            print(f"  \033[33m[i] Passwords Never Expire (Active):\033[0m None found")
            
        print(f"  \033[90m[*] Disabled User Accounts:\033[0m          {len(disabled)} accounts detected")
        
        with open(self.log_file, 'a') as f:
            f.write("==== Detailed Active Directory Insights ====\n")
            f.write(f"High-Privileged Admins (Active): {', '.join(admins) if admins else 'None'}\n")
            f.write(f"Passwords Never Expire (Active): {', '.join(no_expire) if no_expire else 'None'}\n")
            f.write(f"Disabled User Accounts: {', '.join(disabled) if disabled else 'None'}\n\n")

    def enumerate_advanced_attacks(self):
        """Runs the 7 Advanced LDAP Attack Vector Queries."""
        logger.info("[*] Running Advanced Attack Vector LDAP Queries...")
        print("\n\033[1m\033[35m==== AD Attack Vector Identifications ====\033[0m")
        
        # 1. Shadow Credentials (msDS-KeyCredentialLink)
        self.conn.search(self.base_dn, '(msDS-KeyCredentialLink=*)', attributes=['sAMAccountName'])
        shadow_creds = [str(e.sAMAccountName.value) for e in self.conn.entries if 'sAMAccountName' in e and e.sAMAccountName.value]
        if shadow_creds:
            print(f"  \033[31m[!] Shadow Credentials Populated (PKINIT Abuse):\033[0m {', '.join(shadow_creds)}")
            
        # 2. Resource-Based Constrained Delegation (RBCD)
        self.conn.search(self.base_dn, '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)', attributes=['sAMAccountName'])
        rbcd = [str(e.sAMAccountName.value) for e in self.conn.entries if 'sAMAccountName' in e and e.sAMAccountName.value]
        if rbcd:
            print(f"  \033[31m[!] RBCD Configured (msDS-AllowedToActOnBehalfOfOtherIdentity):\033[0m {', '.join(rbcd)}")
            
        # 3. Delegation (Unconstrained & Constrained)
        self.conn.search(self.base_dn, '(userAccountControl:1.2.840.113556.1.4.803:=524288)', attributes=['sAMAccountName'])
        unconstrained = [str(e.sAMAccountName.value) for e in self.conn.entries if 'sAMAccountName' in e and e.sAMAccountName.value and not str(e.sAMAccountName.value).endswith('$')]
        if unconstrained:
            print(f"  \033[31m[!] Unconstrained Delegation (TGT Capture):\033[0m {', '.join(unconstrained)}")
            
        self.conn.search(self.base_dn, '(msDS-AllowedToDelegateTo=*)', attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo'])
        constrained = []
        for e in self.conn.entries:
            if 'sAMAccountName' in e and e.sAMAccountName.value:
                constrained.append(str(e.sAMAccountName.value))
        if constrained:
            print(f"  \033[31m[!] Constrained Delegation Configured:\033[0m {len(constrained)} accounts (Extracting offline via Bloodhound recommended)")
            
        # 4. Extracting gMSA Passwords
        self.conn.search(self.base_dn, '(objectClass=msDS-GroupManagedServiceAccount)', attributes=['sAMAccountName', 'msDS-ManagedPassword'])
        gmsa_read = []
        gmsa_all = []
        for e in self.conn.entries:
            if 'sAMAccountName' in e and e.sAMAccountName.value:
                gmsa_all.append(str(e.sAMAccountName.value))
                if 'msDS-ManagedPassword' in e and e['msDS-ManagedPassword'].value:
                    gmsa_read.append(str(e.sAMAccountName.value))
        if gmsa_all:
            print(f"  \033[33m[i] gMSA Accounts Detected:\033[0m {len(gmsa_all)}")
            if gmsa_read:
                print(f"  \033[31m[!] CRITICAL: You can read gMSA Passwords for:\033[0m {', '.join(gmsa_read)}")
                
        # 5. MachineAccountQuota (MAQ) Evaluation
        self.conn.search(self.base_dn, '(objectClass=domainDNS)', attributes=['ms-DS-MachineAccountQuota'])
        if self.conn.entries:
            maq = getattr(self.conn.entries[0], 'ms-DS-MachineAccountQuota', None)
            if maq and maq.value is not None:
                maq_val = maq.value
                color = "\033[31m" if maq_val > 0 else "\033[32m"
                print(f"  {color}[*] MachineAccountQuota:\033[0m {maq_val} (If > 0, ADCS/RBCD attacks are highly viable)")
                
        # 6. AdminSDHolder Validation Check
        self.conn.search(self.base_dn, '(cn=AdminSDHolder)', attributes=['cn'])
        if self.conn.entries:
            print(f"  \033[32m[+] AdminSDHolder container found.\033[0m Advanced ACL parsing should be done via Bloodhound to detect persistence.")
            
        # 7. Fine-Grained Password Policies (PSOs)
        self.conn.search(self.base_dn, '(objectClass=msDS-PasswordSettings)', attributes=['name'])
        psos = [str(e.name.value) for e in self.conn.entries if 'name' in e and e.name.value]
        if psos:
            print(f"  \033[33m[i] Fine-Grained Password Policies (PSOs) Detected:\033[0m {', '.join(psos)}")
        else:
            print("  \033[32m[i] No Fine-Grained Password Policies (PSOs) found.\033[0m")
            
        with open(self.log_file, 'a') as f:
            f.write("==== AD Attack Vector Identifications ====\n")
            f.write(f"Shadow Credentials: {', '.join(shadow_creds) if shadow_creds else 'None'}\n")
            f.write(f"RBCD Configured: {', '.join(rbcd) if rbcd else 'None'}\n")
            f.write(f"Unconstrained Delegation: {', '.join(unconstrained) if unconstrained else 'None'}\n")
            f.write(f"Constrained Delegation: {', '.join(constrained) if constrained else 'None'}\n")
            f.write(f"Readable gMSA Passwords: {', '.join(gmsa_read) if gmsa_read else 'None'}\n")
            f.write(f"MachineAccountQuota: {maq_val if 'maq' in locals() and maq else 'Default (10)'}\n")
            f.write(f"PSOs Detected: {', '.join(psos) if psos else 'None'}\n")
            logger.info(f"[*] Saved LDAP advanced findings to {self.log_file}")

def run_ldap_enum(domain_controller, domain, username=None, password=None, ntlm_hash=None, workspace='default'):
    """Entry point for the LDAP enumeration module."""
    if not domain_controller:
        logger.error("A Domain Controller IP/Hostname (--dc-ip) is required for LDAP enumeration.")
        return False
        
    scanner = LDAPScanner(domain_controller, domain, username, password, ntlm_hash, workspace)
    if scanner.connect():
        scanner.get_domain_policy()
        scanner.enumerate_users()
        scanner.enumerate_advanced_filters()
        scanner.enumerate_computers()
        scanner.enumerate_advanced_attacks()
        return scanner.domain
        
    return domain
