import os
from .html_exporter import HTMLExporter
try:
    from weasyprint import HTML
except ImportError:
    HTML = None

class PDFExporter:
    def __init__(self, template_dir=None):
        self.html_exporter = HTMLExporter(template_dir)

    def export(self, report_data: dict, output_path: str) -> bool:
        """
        Renders the report data into HTML, then converts to PDF using WeasyPrint.
        """
        if HTML is None:
            raise ImportError("WeasyPrint is not installed or available.")
            
        html_str = self.html_exporter.export(report_data)
        
        # We need to tell WeasyPrint the base_url so it can find styles.css
        base_url = f"file://{os.path.abspath(self.html_exporter.template_dir)}/"
        
        HTML(string=html_str, base_url=base_url).write_pdf(output_path)
        return True
