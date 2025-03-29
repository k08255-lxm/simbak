import subprocess
import logging
import sys

def run_command(command, cwd=None, env=None, shell=False):
    """Executes a shell command and returns stdout, stderr, and return code."""
    try:
        # Use shell=True cautiously, ensure command parts are properly escaped if constructed dynamically
        process = subprocess.run(command, capture_output=True, text=True, check=False, cwd=cwd, env=env, shell=shell)
        return process.stdout, process.stderr, process.returncode
    except FileNotFoundError:
        logging.error(f"Command not found: {command[0] if isinstance(command, list) else command.split()[0]}")
        return None, f"Command not found: {command[0] if isinstance(command, list) else command.split()[0]}", -1
    except Exception as e:
        logging.error(f"Error running command '{command}': {e}")
        return None, str(e), -1

def setup_logging(log_file, log_level_str='INFO'):
    """Configures logging for the agent."""
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Clear existing handlers
    root_logger = logging.getLogger()
    if root_logger.handlers:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(log_level)

    # File Handler
    try:
        file_handler = logging.FileHandler(log_file, mode='a') # Append mode
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        logging.basicConfig(level=log_level, handlers=[console_handler, file_handler])
        logging.info(f"Logging initialized. Level: {log_level_str}. File: {log_file}")
    except Exception as e:
        # Fallback to console only if file logging fails
        logging.basicConfig(level=log_level, handlers=[console_handler])
        logging.error(f"Failed to set up file logging to {log_file}: {e}. Logging to console only.")
