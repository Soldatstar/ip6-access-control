from shared import logging_config

def setup_directories(base_dir, log_file_name, logger_name):
    """
    Sets up the required directories and configures logging.

    Args:
        base_dir (Path): The base directory for policies and logs.
        log_file_name (str): The name of the log file.
        logger_name (str): The name of the logger.

    Returns:
        tuple: A tuple containing the paths to the policies directory, logs directory, and logger.
    """
    policies_dir = base_dir / "policies"
    logs_dir = base_dir / "logs"

    # Ensure required directories exist
    policies_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Configure logging
    log_file_path = logs_dir / log_file_name
    logger = logging_config.configure_logging(log_file_path, logger_name)

    return policies_dir, logs_dir, logger
