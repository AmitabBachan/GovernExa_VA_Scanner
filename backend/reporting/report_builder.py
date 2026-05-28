import os
from datetime import datetime
from typing import Dict, Any

from .pdf_generator import PDFGenerator
from .csv_generator import CSVGenerator
from .json_generator import JSONGenerator

class ReportBuilder:
    """
    Orchestrates the generation of different report formats and types.
    """
    def __init__(self, output_dir: str = "/tmp/reports"):
        self.output_dir = output_dir
        self.pdf_gen = PDFGenerator(output_dir)
        self.csv_gen = CSVGenerator(output_dir)
        self.json_gen = JSONGenerator(output_dir)

    def generate_report(self, data: Dict[str, Any], report_format: str, report_type: str) -> str:
        """
        data: Dict containing the context (e.g. scan results, findings)
        report_format: 'pdf', 'csv', 'json'
        report_type: 'executive', 'technical', 'remediation'
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnscope_{report_type}_{timestamp}"
        
        if report_format.lower() == "pdf":
            return self.pdf_gen.generate(data, filename, report_type)
        elif report_format.lower() == "csv":
            return self.csv_gen.generate(data, filename, report_type)
        elif report_format.lower() == "json":
            return self.json_gen.generate(data, filename)
        else:
            raise ValueError(f"Unsupported report format: {report_format}")
