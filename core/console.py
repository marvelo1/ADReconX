import sys
import os
import json
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import ANSI
from core.logger import setup_logger

logger = setup_logger()

# Basic commands for the console
ADRECONX_COMMANDS = [
    'help', 'exit', 'set', 'options', 'workspace', 'auth', 'info', 
    'run enum', 'run dns', 'run ldap', 'run smb', 
    'help', 'exit', 'workspace', 'auth', 'set', 'options',
    'run enum', 'run sweep', 'run dns', 'run ldap', 'run smb', 'run mssql',
    'run asreproast', 'run kerberoast', 'run adcs', 'run adcs-exploit', 'run rbcd',
    'run bloodhound', 'run auto-exploit', 'run dcsync', 'run spray', 'run report', 'run lpe'
]

def print_help():
    print("""
\033[33m==== ADReconX Interactive Console ====\033[0m
\033[1mCore Commands:\033[0m
  help        - Show this help menu
  exit        - Exit the console
  workspace   - Switch or create a new workspace (e.g., workspace client_x)
  auth        - Quick-configure Authentication (see: auth help)
  set         - Set global options (e.g., set domain pirate.htb)
  options     - View current configured options

\033[1mRecon & Enum Modules:\033[0m
  run sweep <cidr> - High-speed multi-host AD sweep (e.g. run sweep 192.168.1.0/24)
  run enum        - Execute full basic enumeration (DNS, LDAP, SMB)
  run dns         - Execute DNS SRV and Zone Transfer checks
  run ldap        - Execute LDAP user enumeration
  run smb         - Execute SMB share crawling & GPP password extraction
  run mssql [ip]  - Execute MSSQL auto-login and xp_cmdshell auto-RCE

\033[1mExploitation Modules:\033[0m
  run asreproast  - Hunt for AS_REP kerberos hashes
  run kerberoast  - Hunt for Kerberoastable Service Accounts
  run adcs        - Execute Certipy to find vulnerable ESC templates
  run adcs-exploit- Exploit ESC1 to request Domain Admin Certificate
  run rbcd <targ> <ctrl> - Attempt Resource-Based Constrained Delegation

\033[1mPost-Exploitation Modules:\033[0m
  run bloodhound  - Collect AD topology via Bloodhound-Python
  run auto-exploit- Algorithmic Attack Path generation (Requires Bloodhound Data)
  run dcsync      - Attempt NTDS.dit extraction via secretsdump
  run spray       - Execute safe password spraying against domain
  run lpe <param> - AMSI Bypass & Memory Injection (powerup, winpeas, basic)
  run report      - Generate Markdown MITRE ATT&CK Report from workspace
""")

def save_workspace_config(workspace_dir, global_options):
    """Saves the current global options to the workspace config file."""
    config_path = os.path.join(workspace_dir, 'config.json')
    try:
        with open(config_path, 'w') as f:
            json.dump(global_options, f, indent=4)
    except Exception as e:
        logger.error(f"Failed to save workspace config: {e}")

def load_workspace_config(workspace_dir, current_options):
    """Loads options from the workspace config file if it exists."""
    config_path = os.path.join(workspace_dir, 'config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                saved_config = json.load(f)
                for k, v in saved_config.items():
                    if k in current_options:
                        current_options[k] = v
            logger.info(f"[*] Loaded saved configuration from workspace.")
        except Exception as e:
            logger.error(f"Failed to load workspace config: {e}")
    return current_options

def start_interactive_console(global_args):
    """
    Starts the prompt_toolkit interactive CLI.
    """
    logger.info("Initializing ADReconX Interactive Console...")
    
    session = PromptSession(
        history=InMemoryHistory(),
        auto_suggest=AutoSuggestFromHistory(),
        completer=WordCompleter(ADRECONX_COMMANDS, ignore_case=True, match_middle=True)
    )

    # Context variables
    global_options = {
        'DOMAIN': global_args.domain or '',
        'DC_IP': global_args.dc_ip or '',
        'USERNAME': global_args.username or '',
        'PASSWORD': global_args.password or '',
        'HASHES': global_args.hashes or '',
        'WORKSPACE': global_args.workspace or 'default'
    }
    
    # Initialize workspace
    workspace_dir = os.path.join(os.getcwd(), 'workspaces', global_options['WORKSPACE'])
    if not os.path.exists(workspace_dir):
        os.makedirs(workspace_dir)
        save_workspace_config(workspace_dir, global_options)
    else:
        # Load existing config if we are booting into an existing workspace
        global_options = load_workspace_config(workspace_dir, global_options)
        
    print("\n\033[36mType 'help' for a list of commands, or 'exit' to quit.\033[0m")
    
    while True:
        try:
            from prompt_toolkit import HTML
            # Show a metasploit-style prompt
            target_display = global_options['DOMAIN'] or global_options['DC_IP'] or 'Unset'
            prompt_text = HTML(f"<b><ansiblue>ADReconX</ansiblue></b>[<ansired>{target_display}</ansired>] > ")
            text = session.prompt(prompt_text)
            
            if not text.strip():
                continue
                
            parts = text.strip().split()
            command = parts[0].lower()
            args = parts[1:]

            if command == 'exit':
                logger.info("Exiting interactive mode...")
                break
                
            elif command == 'help':
                print_help()
                
            elif command == 'set':
                if len(args) >= 2:
                    opt = args[0].upper()
                    val = " ".join(args[1:])
                    if opt in global_options:
                        global_options[opt] = val
                        logger.info(f"{opt} => {val}")
                        # Remake workspace if they change it
                        if opt == 'WORKSPACE':
                            workspace_dir = os.path.join(os.getcwd(), 'workspaces', global_options['WORKSPACE'])
                            if not os.path.exists(workspace_dir):
                                os.makedirs(workspace_dir)
                                save_workspace_config(workspace_dir, global_options)
                            else:
                                global_options = load_workspace_config(workspace_dir, global_options)
                        else:
                            # Save state for standard option changes
                            save_workspace_config(os.path.join(os.getcwd(), 'workspaces', global_options['WORKSPACE']), global_options)
                    else:
                        logger.warning(f"Unknown option to set: {opt}")
                else:
                    logger.warning("Usage: set <OPTION> <VALUE>")
                    
            elif command == 'workspace':
                if len(args) >= 1:
                    new_ws = args[0]
                    global_options['WORKSPACE'] = new_ws
                    workspace_dir = os.path.join(os.getcwd(), 'workspaces', new_ws)
                    if not os.path.exists(workspace_dir):
                        os.makedirs(workspace_dir)
                        logger.info(f"[*] Created new workspace: {workspace_dir}")
                        save_workspace_config(workspace_dir, global_options)
                    else:
                        logger.info(f"[*] Switched to existing workspace: {workspace_dir}")
                        global_options = load_workspace_config(workspace_dir, global_options)
                else:
                    logger.warning(f"Current workspace: {global_options['WORKSPACE']}. Usage: workspace <name>")

            elif command == 'auth':
                if len(args) == 0 or args[0].lower() == 'help':
                    print("\n\033[1mAuthentication Setup:\033[0m")
                    print("  auth <username> <password>  - Set authenticated user/password setup")
                    print("  auth <username> -H <hash>   - Set Pass-the-Hash setup")
                    print("  auth clear                  - Clear credentials (forces Unauthenticated/Anonymous binding)")
                    print()
                elif len(args) == 1 and args[0].lower() == 'clear':
                    global_options['USERNAME'] = ''
                    global_options['PASSWORD'] = ''
                    global_options['HASHES'] = ''
                    logger.info("[*] Cleared credentials. Operations will run Unauthenticated (Anonymous Binding).")
                    save_workspace_config(os.path.join(os.getcwd(), 'workspaces', global_options['WORKSPACE']), global_options)
                elif len(args) >= 2:
                    global_options['USERNAME'] = args[0]
                    if args[1] == '-H' or args[1] == '--hashes':
                        global_options['HASHES'] = args[2] if len(args) > 2 else ''
                        global_options['PASSWORD'] = ''
                        logger.info(f"[*] Auth set to Pass-the-Hash for user: {args[0]}")
                    else:
                        global_options['PASSWORD'] = " ".join(args[1:])
                        global_options['HASHES'] = ''
                        logger.info(f"[*] Auth set to Password for user: {args[0]}")
                    save_workspace_config(os.path.join(os.getcwd(), 'workspaces', global_options['WORKSPACE']), global_options)
                        
            elif command == 'options':
                print("\n\033[1mGlobal Options:\033[0m")
                print(f"  {'Option':<15} {'Value':<30}")
                print(f"  {'------':<15} {'-----':<30}")
                for k, v in global_options.items():
                    print(f"  {k:<15} {str(v):<30}")
                print()
                
            elif command == 'run':
                if len(args) == 0:
                    logger.warning("Usage: run <module_name>")
                    continue
                    
                module = args[0].lower()
                
                # Check required options for most modules
                if module not in ['sweep', 'report', 'mssql'] and not global_options['DC_IP']:
                    logger.error("Missing required parameter: DC_IP. Type 'set DC_IP <ip_address>'")
                    continue
                    
                if module == 'mssql' and not global_options['DC_IP'] and len(args) < 2:
                    logger.error("Missing target IP. Type 'run mssql <ip>' or 'set DC_IP <ip>'")
                    continue
                    
                dc = global_options['DC_IP']
                dom = global_options['DOMAIN']
                usr = global_options['USERNAME']
                pwd = global_options['PASSWORD']
                hsh = global_options['HASHES']
                ws = global_options['WORKSPACE']
                
                if module == 'sweep':
                    if len(args) < 2:
                        logger.error("Usage: run sweep <IP_or_CIDR>")
                        continue
                    from modules.enum.sweep import run_network_sweep
                    run_network_sweep(args[1], ws)
                    continue

                if module == 'enum':
                    logger.info(f"[*] Running basic enumeration wrapper...")
                    from modules.enum.dns_enum import run_dns_enum
                    from modules.enum.ldap_enum import run_ldap_enum
                    from modules.enum.smb_enum import run_smb_enum
                    run_dns_enum(dc, dom)
                    dom = run_ldap_enum(dc, dom, usr, pwd, hsh, ws)
                    if dom: global_options['DOMAIN'] = dom
                    run_smb_enum(dc, usr, pwd, hsh, ws)
                    
                elif module == 'dns':
                    from modules.enum.dns_enum import run_dns_enum
                    run_dns_enum(dc, dom)
                    
                elif module == 'ldap':
                    from modules.enum.ldap_enum import run_ldap_enum
                    dom = run_ldap_enum(dc, dom, usr, pwd, hsh, ws)
                    if dom: global_options['DOMAIN'] = dom
                    
                elif module == 'mssql':
                    from modules.enum.mssql_enum import run_mssql_enum
                    target_ip = args[1] if len(args) > 1 else dc
                    logger.info(f"[*] Starting MSSQL enumeration against {target_ip}...")
                    run_mssql_enum(target_ip, dom, usr, pwd, hsh)
                    
                elif module == 'smb':
                    from modules.enum.smb_enum import run_smb_enum
                    run_smb_enum(dc, usr, pwd, hsh, ws)
                    
                elif module == 'asreproast':
                    from modules.exploit.kerberos import run_asreproast
                    run_asreproast(dc, dom, usr, pwd, hsh)
                    
                elif module == 'kerberoast':
                    from modules.exploit.kerberos import run_kerberoast
                    run_kerberoast(dc, dom, usr, pwd, hsh)
                    
                elif module == 'adcs':
                    from modules.exploit.adcs import check_adcs
                    check_adcs(dc, dom, usr, pwd, hsh, ws)
                    
                elif module == 'adcs-exploit':
                    from modules.exploit.advanced.adcs_exploit import exploit_adcs_esc1
                    exploit_adcs_esc1(dc, dom, usr, pwd, hsh, ws)
                    
                elif module == 'rbcd':
                    if len(args) < 3:
                        logger.error("Usage: run rbcd <target_machine$> <controlled_machine$>")
                        continue
                    from modules.exploit.advanced.rbcd import exploit_rbcd
                    target_machine = args[1]
                    controlled_machine = args[2]
                    exploit_rbcd(dc, dom, usr, pwd, target_machine, controlled_machine, ws)
                    
                elif module == 'bloodhound':
                    from modules.bloodhound.collector import run_bloodhound
                    run_bloodhound(dc, dom, usr, pwd, hsh, ws)
                    
                elif module == 'auto-exploit':
                    from modules.bloodhound.pathfinder import execute_attack_path
                    execute_attack_path(dc, dom, ws)
                 
                elif module == 'dcsync':
                    from modules.post.cred_harvest import run_credential_harvesting
                    run_credential_harvesting(dc, dom, usr, pwd, hsh, ws)
                    
                elif module == 'lpe':
                    from modules.post.lpe_checks import run_lpe_module
                    if len(args) < 2:
                        logger.error("Usage: run lpe <basic|powerup|winpeas> [optional_url_override]")
                        logger.warning("Example: run lpe powerup")
                        continue
                        
                    lpe_mode = args[1].lower()
                    script_url = args[2] if len(args) > 2 else None
                    target = global_options['DC_IP']
                    run_lpe_module(target, dom, usr, pwd, hsh, lpe_mode, script_url)
                    
                elif module == 'spray':
                    from modules.post.password_spray import run_password_spray
                    pass_list = " ".join(args[1:]) if len(args) > 1 else None
                    run_password_spray(dc, dom, usr, pwd, hsh, ws, pass_list=pass_list)
                    
                elif module == 'report':
                    from modules.report.generator import generate_report
                    generate_report(dom, ws)
                    
                else:
                    logger.warning(f"[-] Unknown module: {module}. Type 'help' for available modules.")

            else:
                logger.warning(f"Unknown command: {command}")
                
        except KeyboardInterrupt:
            # Catch Ctrl+C inside the loop to cancel current line without exiting
            print()
            continue
        except EOFError:
            # Catch Ctrl+D to exit
            break
        except Exception as e:
            logger.error(f"Console error: {str(e)}")
