import json

class JSONExporter:
    def __init__(self):
        pass

    def export(self, report_data: dict, output_path: str) -> bool:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4, default=lambda o: o.__dict__)
        return True
