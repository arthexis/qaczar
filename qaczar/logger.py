import os
import logging


def init_logger(level: str = "INFO"):
    """Initialize the QACZAR default logger."""
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s %(levelname)s %(module)s.%(funcName)s:%(lineno)d %(message)s",
        handlers=[
            logging.FileHandler(os.path.join(project_dir, "qaczar.log")),
            logging.StreamHandler()
        ]
    )
