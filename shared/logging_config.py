import logging

def configure_logging(log_file_name, logger_name): #pragma: no cover 
    #TODO: Implement various logging level and argument to set the level 
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    # Remove any default handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # File handler
    file_handler = logging.FileHandler(log_file_name)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(f"[{logger_name}] %(message)s"))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(f"[{logger_name}] %(message)s"))

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger