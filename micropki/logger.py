import logging
import sys
from datetime import datetime, timezone


class MillisecondFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        ct = datetime.fromtimestamp(record.created, timezone.utc)
        return ct.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def setup_logger(log_file=None):
    logger = logging.getLogger("micropki")
    logger.setLevel(logging.DEBUG)

    # Очистка старых хэндлеров
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = MillisecondFormatter('%(asctime)s - %(levelname)s - %(message)s')

    if log_file:
        ch = logging.FileHandler(log_file, encoding='utf-8')
    else:
        ch = logging.StreamHandler(sys.stderr)

    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger