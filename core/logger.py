import logging
from rich.logging import RichHandler
from rich.console import Console

console = Console()

def setup_logger(level=logging.INFO):
    """
    Sets up a rich-formatted logger for professional output.
    """
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True, show_path=False)]
    )

    logger = logging.getLogger("ADReconX")
    return logger
