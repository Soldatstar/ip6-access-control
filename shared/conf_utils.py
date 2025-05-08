from pathlib import Path
from shared import logging_config
BASE_DIR = Path(__file__).resolve().parent.parent / "process-supervisor"
POLICIES_DIR = BASE_DIR / "policies"
LOGS_DIR = BASE_DIR / "logs"

def setup_directories(log_file_name, logger_name):
    """
    Sets up the required directories and configures logging.

    Args:
        log_file_name (str): The name of the log file.
        logger_name (str): The name of the logger.

    Returns:
        tuple: A tuple containing the paths to the policies directory, logs directory, and logger.
    """
    # Ensure required directories exist
    POLICIES_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # Configure logging
    log_file_path = LOGS_DIR / log_file_name
    logger = logging_config.configure_logging(log_file_path, logger_name)

    return POLICIES_DIR, LOGS_DIR, logger
