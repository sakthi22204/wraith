import pytest
from app.pdf_export import pdf_exporter

def test_jinja2_autoescape():
    # Test that HTML tags in description are escaped
    report_data = {
        "title": "Test Report",
        "findings": [
            {
                "vuln_type": "XSS",
                "severity": "High",
                "description": "<script>alert(1)</script>",
                "recommendation": "Fix it"
            }
        ],
        "program_name": "Test Program"
    }

    # We'll use a mock of env to render the template and check the output
    # but we already configured it in app.pdf_export.
    # To test it properly, we can just render a string using the configured env.
    from app.pdf_export import env

    # Create a dummy template in memory
    template = env.from_string("Description: {{ findings[0].description }}")
    rendered = template.render(**report_data)

    assert "<script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered

def test_jinja2_no_autoescape_markdown():
    # If we had a markdown template, we might want to check if it escapes too.
    # But usually autoescape is for HTML/XML.
    # If we use a .md extension, select_autoescape(["html", "j2", "xml"]) should NOT match it.
    from app.pdf_export import env
    from jinja2 import Template

    # select_autoescape matches by template name.
    # If we don't provide a name, it uses default.

    # Let's test with a mock filename
    from datetime import datetime
    template_html = env.get_template("finding_report.html.j2")
    # Provide all required fields to avoid UndefinedError
    finding = {
        "description": "<script>",
        "vuln_type": "x",
        "severity": "y",
        "recommendation": "z",
        "discovery_metadata": {"status": "UNCONFIRMED", "discovered_at": datetime.utcnow()},
        "cvss": {"score": 7.5, "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "target": {"type": "endpoint", "identifier": "http://test"}
    }
    rendered_html = template_html.render(
        findings=[finding],
        program_name="test",
        generated_at=datetime.utcnow()
    )
    assert "&lt;script&gt;" in rendered_html
