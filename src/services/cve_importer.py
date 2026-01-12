from typing import Dict, List
from sqlalchemy.orm import Session


def save_cves(cve_objects: List[Dict], db: Session) -> bool:
    return True
