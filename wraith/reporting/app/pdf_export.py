import weasyprint
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os

template_dir = os.path.join(os.path.dirname(__file__), "templates")
env = Environment(
    loader=FileSystemLoader(template_dir),
    autoescape=select_autoescape(["html", "j2", "xml"])
)

class PDFExporter:
    def export_report(self, report_data: dict, template_name: str = "finding_report.html.j2") -> bytes:
        template = env.get_template(template_name)
        html_out = template.render(**report_data)

        pdf_bytes = weasyprint.HTML(string=html_out).write_pdf()
        return pdf_bytes

pdf_exporter = PDFExporter()
