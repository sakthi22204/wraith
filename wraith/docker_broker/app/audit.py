import logging
from datetime import datetime

logger = logging.getLogger("docker_broker_audit")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def audit_log(operation: str, target: str, allowed: bool, reason: str = None):
    status = "ALLOWED" if allowed else "REJECTED"
    msg = f"[{status}] Op: {operation}, Target: {target}"
    if reason:
        msg += f", Reason: {reason}"
    logger.info(msg)
