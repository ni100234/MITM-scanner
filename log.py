import os
import logging
from logging.handlers import RotatingFileHandler

LOG_FOLDER = 'logs'
LOG_FILE_SIZE_LIMIT = 5 * 1024 * 1024  # 5 MB in bytes

if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Rotating file handler with size-based rotation
handler = RotatingFileHandler(
    filename=os.path.join(LOG_FOLDER, 'log.txt'),
    maxBytes=LOG_FILE_SIZE_LIMIT,
    backupCount=9999
)
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

def log(message):
    logger.info(message)

if __name__ == '__main__':
    log('Logging initialized')
