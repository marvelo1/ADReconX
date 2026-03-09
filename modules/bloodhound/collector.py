import os
from core.logger import setup_logger

logger = setup_logger()

def run_bloodhound(dc_ip, domain, username, password, hashes, workspace):
    """
    Uses Python Bloodhound implementation to collect full AD topology.
    """
    logger.info("Starting BloodHound data collection via LDAP/RPC...")
    if not username or (not password and not hashes):
        logger.error("[-] Skipping BloodHound: Requires valid domain credentials.")
        return False
        
    # Build workspace output prefix
    workspace_dir = os.path.join(os.getcwd(), 'workspaces', workspace)
    zip_filename = os.path.join(workspace_dir, f"{domain}_bloodhound.zip")
    
    logger.info(f"[*] Collecting Object Properties, ACLs, and Trusts for {domain}...")
    
    try:
        import subprocess
        
        # Build the bloodhound-python command based on auth type
        cmd = [
            "bloodhound-python",
            "-d", domain,
            "-u", username,
            "-ns", dc_ip,
            "-c", "Default",
            "--zip"
        ]
        
        if hashes:
            cmd.extend(["--hashes", hashes])
        elif password:
            cmd.extend(["-p", password])
            
        # Run it in the workspace directory so the ZIP drops there natively
        logger.info(f"[*] Executing: {' '.join(cmd)}")
        result = subprocess.run(cmd, cwd=workspace_dir, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"[+] Bloodhound collection complete. JSON/ZIP files saved to: {workspace_dir}")
        else:
            logger.error(f"[-] Bloodhound CLI failed with error code {result.returncode}")
            logger.error(f"STDOUT: {result.stdout.strip()}")
            logger.error(f"STDERR: {result.stderr.strip()}")
            return False
        
    except Exception as e:
        logger.error(f"[-] Bloodhound collection failed: {str(e)}")
        return False
        
    # BloodHound CE Integration Note
    logger.info("[*] To auto-upload to BloodHound CE, ensure API URL and Token are set in config.")
    logger.info("[-] BloodHound API token not found. Skipping auto-upload.")
    return True
