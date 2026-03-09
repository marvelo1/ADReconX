from rich.prompt import Confirm
from core.logger import setup_logger

logger = setup_logger()

def ask_permission(module_name, risk_level="Low"):
    """
    Prompts the user for execution permission.
    """
    logger.warning(f"\n[!] Preparing to run module: {module_name} (Risk Level: {risk_level})")
    
    # Using rich.prompt.Confirm for a stylish Y/n prompt
    return Confirm.ask(f"[bold yellow]Do you want to execute {module_name}?[/bold yellow]")
