import os
from jinja2 import Environment, FileSystemLoader

class HTMLExporter:
    def __init__(self, template_dir=None):
        if template_dir is None:
            # Default to backend/reporting/templates
            current_dir = os.path.dirname(os.path.abspath(__file__))
            template_dir = os.path.join(current_dir, '..', 'templates')
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(self.template_dir))

    def export(self, report_data: dict, output_path: str = None) -> str:
        """
        Renders the report data into HTML using Jinja2 templates.
        Returns the HTML string, and optionally writes to output_path.
        """
        template = self.env.get_template('index.html')
        html_out = template.render(report=report_data)
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_out)
                
        return html_out
