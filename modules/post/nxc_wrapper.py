import subprocess
import os
from core.logger import setup_logger

logger = setup_logger()

def run_netexec(target, protocol, module, domain, username, password, ntlm_hash=None, extra_args=""):
    """
    Executes NetExec (nxc) with the provided ADReconX authentication variables to 
    seamlessly run post-exploitation modules like winpeas, amsi bypasses, and CVE checks.
    """
    logger.info(f"[*] Initializing NetExec Integration Wrapper...")
    
    # Base command
    cmd = ["nxc", protocol, target]
    
    # Authentication
    cmd.extend(["-u", username])
    if password:
        cmd.extend(["-p", password])
    elif ntlm_hash:
        cmd.extend(["-H", ntlm_hash])
        
    if domain:
        cmd.extend(["-d", domain])
        
    # Module execution
    if module:
        cmd.extend(["-M", module])
        
    # Any custom arguments supplied by user
    if extra_args:
        cmd.extend(extra_args.split())

    cmd_str = " ".join(cmd)
    logger.info(f"[+] Executing: \033[36m{cmd_str}\033[0m\n")
    
    try:
        # We use Popen so the user sees the output streaming in real-time
        process = subprocess.Popen(cmd_str, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in process.stdout:
            print(line.rstrip())
        process.wait()
        
        if process.returncode == 0:
            logger.info("[+] NetExec module completed successfully.")
            return True
        else:
            logger.error(f"[-] NetExec exited with code {process.returncode}")
            return False
            
    except Exception as e:
        logger.error(f"[-] Failed to execute NetExec: {e}")
        logger.warning("[!] Is 'nxc' installed on your system? (apt install netexec)")
        return False
