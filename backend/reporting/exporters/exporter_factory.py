from .html_exporter import HTMLExporter
from .pdf_exporter import PDFExporter
from .docx_exporter import DOCXExporter
from .csv_exporter import CSVExporter
from .xlsx_exporter import XLSXExporter
from .json_exporter import JSONExporter

class ExporterFactory:
    @staticmethod
    def get_exporter(format_type: str, template_dir: str = None):
        format_type = format_type.lower()
        if format_type == 'html':
            return HTMLExporter(template_dir)
        elif format_type == 'pdf':
            return PDFExporter(template_dir)
        elif format_type == 'docx':
            return DOCXExporter()
        elif format_type == 'csv':
            return CSVExporter()
        elif format_type == 'xlsx':
            return XLSXExporter()
        elif format_type == 'json':
            return JSONExporter()
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
