import sys
import os
import logging

logging.basicConfig(level=os.getenv('LOGLEVEL', 'WARNING').upper(), force=True)

logger = logging.getLogger("acs")
logger.propagate = False
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    "[{levelname:^7}] {asctime} {name}: {message}",
    datefmt="%H:%M:%S",
    style="{",
)
handler.setFormatter(formatter)
logger.addHandler(handler)
