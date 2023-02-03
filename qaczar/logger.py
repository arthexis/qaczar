import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler("qaczar.log"),
        logging.StreamHandler()
    ]
)


__all__ = []
