import json
import os
from typing import Dict, Any

class JSONGenerator:
    """
    Generates machine-readable JSON reports.
    """
    def __init__(self, output_dir: str = "/tmp/reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate(self, data: Dict[str, Any], filename: str) -> str:
        filepath = os.path.join(self.output_dir, f"{filename}.json")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        return filepath
