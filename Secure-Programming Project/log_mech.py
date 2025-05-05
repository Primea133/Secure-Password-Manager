import logging
import os

def get_logging_path():
    # Get the LOCALAPPDATA path
    # Create a directory for the logging
    secure_folder = os.path.join(os.getenv("LOCALAPPDATA"), "MyPasswordManager")
    # Ensure the folder exists
    os.makedirs(secure_folder, exist_ok=True)
    return os.path.join(secure_folder, "logs.log")

# Log config
logging.basicConfig(
    level=logging.INFO, #level=logging.DEBUG
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        # Log to file
        logging.FileHandler(get_logging_path()), 
        # Print to console function
        #logging.StreamHandler()
    ]
)

# Function to use for logging
def log_event(message):
    logging.info(message)