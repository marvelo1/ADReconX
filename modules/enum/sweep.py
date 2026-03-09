import socket
import concurrent.futures
import ipaddress
import os
import subprocess
from core.logger import setup_logger

logger = setup_logger()

# Map common port numbers to service names for the fast scanner
PORT_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    88: "Kerberos",
    135: "RPC",
    139: "NetBIOS",
    161: "SNMP",
    389: "LDAP",
    445: "SMB",
    636: "LDAPS",
    3268: "GlobalCatalog",
    3389: "RDP",
    5985: "WinRM"
}

def scan_port(ip, port, timeout=1.0):
    try:
        # SNMP is UDP, socket check might fail for UDP if we only use SOCK_STREAM.
        # So for 161, we'll try a quick UDP check if needed, but for now we'll send standard TCP probes
        sock_type = socket.SOCK_DGRAM if port == 161 else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, sock_type) as s:
            s.settimeout(timeout)
            if sock_type == socket.SOCK_DGRAM:
                # Basic SNMP v1/v2c query payload for "public" community
                snmp_query = b'\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x13\x37\x13\x37\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'
                s.sendto(snmp_query, (str(ip), port))
                data, _ = s.recvfrom(1024)
                if data: return port
            else:
                if s.connect_ex((str(ip), port)) == 0:
                    return port
    except Exception:
        pass
    return None

def scan_host(ip):
    ports_to_check = list(PORT_MAP.keys())
    open_ports = []
    
    for port in ports_to_check:
        if scan_port(ip, port, timeout=0.5):
            open_ports.append(port)
            
    return ip, open_ports

def run_nmap_detailed_scan(ip_list, ports, workspace_dir):
    """
    Takes the live IPs and their open ports, and runs an intensive Nmap scan 
    to extract service banners, versions, and SMB details.
    """
    logger.info("[*] Invoking Nmap to grab detailed service banners and vulnerability checks on live hosts...")
    out_file = os.path.join(workspace_dir, "nmap_detailed_sweep.txt")
    
    # We'll just run nmap against the specific open ports discovered to save massive amounts of time
    all_ports = ",".join(map(str, set(p for ports in ports.values() for p in ports)))
    target_ips = ",".join(ip_list)
    
    if not all_ports or not target_ips:
        return
        
    try:
        command = [
            'nmap', '-Pn', '-sV', '-sC', 
            '-p', all_ports,
            target_ips
        ]
        
        logger.info(f"[*] Running: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True)
        
        with open(out_file, 'w') as f:
            f.write(result.stdout)
            
        print("\n\033[1m\033[36m==== Detailed Nmap Service Output ====\033[0m")
        print(result.stdout)
        logger.info(f"[*] Detailed Nmap results saved to {out_file}")
        
    except Exception as e:
        logger.error(f"[-] Nmap is not installed or failed to run: {e}")

def run_network_sweep(target_range: str, workspace: str):
    logger.info(f"[*] Starting multi-host network sweep against {target_range}")
    workspace_dir = os.path.join(os.getcwd(), 'workspaces', workspace)
    out_file = os.path.join(workspace_dir, "network_sweep_fast.txt")
    
    # parse cidr or single IP
    try:
        if '/' in target_range:
            ips = list(ipaddress.ip_network(target_range, strict=False).hosts())
        else:
            ips = [ipaddress.ip_address(target_range)]
    except ValueError as e:
        logger.error(f"[-] Invalid IP range: {e}")
        return
        
    logger.info(f"[*] High-speed scanning {len(ips)} hosts for AD & Infrastructure services...")
    
    live_hosts = {}
    dc_candidates = []
    
    # Thread pool for fast scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip = {executor.submit(scan_host, ip): ip for ip in ips}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                ip_addr, open_ports = future.result()
                if open_ports:
                    live_hosts[str(ip_addr)] = open_ports
                    
                    # Is it a DC? (usually has 88 and 389)
                    if 88 in open_ports and 389 in open_ports:
                        dc_candidates.append(str(ip_addr))
                        
            except Exception as e:
                pass
                
    # Display results
    print("\n\033[1m\033[36m==== Multi-Host Fast Sweep Results ====\033[0m")
    
    if dc_candidates:
        print("\n\033[1m\033[31m[!] Potential Domain Controllers Identified:\033[0m")
        for dc in dc_candidates:
            print(f"  --> \033[31m{dc}\033[0m")
            
    print("\n\033[1m[+] Live Hosts Discovered:\033[0m")
    
    output_lines = ["==== Multi-Host Sweep Results ====\n"]
    if dc_candidates:
         output_lines.append("[!] Potential Domain Controllers Identified:")
         for dc in dc_candidates:
             output_lines.append(f"  --> {dc}")
    output_lines.append("\n[+] Live Hosts:")
    
    for host, ports in live_hosts.items():
        # Map port numbers to friendly names
        friendly_ports = [f"{p}({PORT_MAP.get(p, 'Unknown')})" for p in ports]
        port_str = ", ".join(friendly_ports)
        msg = f"  {host:<15} : {port_str}"
        print(msg)
        output_lines.append(msg)
        
    summary = f"\n[*] Total live hosts: {len(live_hosts)} / {len(ips)}"
    print(summary)
    output_lines.append(summary)
    
    # Save to workspace
    with open(out_file, "w") as f:
        f.write("\n".join(output_lines))
        
    logger.info(f"[*] Fast network map saved to {out_file}")
    
    # 2. Automatically launch detailed Nmap scan on the detected open ports!
    if live_hosts:
        run_nmap_detailed_scan(list(live_hosts.keys()), live_hosts, workspace_dir)
    
    return live_hosts, dc_candidates
