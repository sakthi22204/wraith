from fastapi import APIRouter, HTTPException, Query, Response, Depends
from ..generator import generator
from ..auth import require_admin_token
from ..pdf_export import pdf_exporter
from ..clients.graph_db_client import graph_db_client
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import os

router = APIRouter()

template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")


def _autoescape(template_name):
    """Escape HTML templates, never the markdown one.

    ``select_autoescape(["html", "j2", "xml"])`` classified every template as
    HTML because both names end in ``.j2``, so the markdown body rendered as
    ``&#39;`` instead of ``'`` -- valid HTML, unreadable plain text.
    """
    return bool(template_name) and (
        template_name.endswith(".html") or template_name.endswith(".html.j2")
    )


env = Environment(
    loader=FileSystemLoader(template_dir),
    autoescape=_autoescape,
)

import logging

logger = logging.getLogger(__name__)

def parse_date(ts):
    if not ts: return datetime.utcnow()
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError as e:
        logger.warning(f"Malformed ISO date string encountered in parse_date: '{ts}'. Fallback to utcnow. Error: {e}")
        return datetime.utcnow()

# Primary Investigation Report routes
@router.get("/reports/{investigation_id}/findings/{finding_id}", dependencies=[Depends(require_admin_token)])
async def get_finding_report(investigation_id: str, finding_id: str, format: str = Query("markdown", pattern="^(markdown|pdf|html|json)$")):
    finding = await graph_db_client.get_finding(investigation_id, finding_id)

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    report_finding = await generator.generate_finding_report(investigation_id, finding)
    investigation_data = await graph_db_client.get_investigation(investigation_id)

    report_data = {
        "program_name": investigation_data.get("name", "Unknown") if investigation_data else "Unknown",
        "generated_at": parse_date(report_finding.discovery_metadata["timestamp"]),
        "findings": [report_finding]
    }

    if format == "pdf":
        pdf_bytes = pdf_exporter.export_report(report_data)
        return Response(content=pdf_bytes, media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=finding_{finding_id}.pdf"
        })
    elif format == "html":
        template = env.get_template("finding_report.html.j2")
        # Ensure dates and timestamps are serializable / formatted in the template
        html_out = template.render(**report_data)
        return Response(content=html_out, media_type="text/html", headers={
            "Content-Disposition": f"attachment; filename=finding_{finding_id}.html"
        })
    elif format == "json":
        return report_finding
    else:
        template = env.get_template("finding_report.md.j2")
        md_out = template.render(**report_data)
        return Response(content=md_out, media_type="text/markdown")

@router.get("/reports/{investigation_id}", dependencies=[Depends(require_admin_token)])
async def get_investigation_report(
    investigation_id: str,
    format: str = Query("markdown", pattern="^(markdown|pdf|html|json)$"),
    profile: str = Query("auto", pattern="^(auto|bugcrowd|hackerone|redteam)$"),
):
    report = await generator.generate_program_report(investigation_id, profile=profile)
    report_data = report.model_dump()

    if format == "pdf":
        pdf_bytes = pdf_exporter.export_report(report_data)
        return Response(content=pdf_bytes, media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=investigation_{investigation_id}.pdf"
        })
    elif format == "html":
        template = env.get_template("finding_report.html.j2")
        html_out = template.render(**report_data)
        return Response(content=html_out, media_type="text/html", headers={
            "Content-Disposition": f"attachment; filename=investigation_{investigation_id}.html"
        })
    elif format == "json":
        return report
    else:
        template = env.get_template("finding_report.md.j2")
        md_out = template.render(**report_data)
        return Response(content=md_out, media_type="text/markdown")

# Backwards compatible alias program endpoints
@router.get("/reports/program/{program_id}/findings/{finding_id}", dependencies=[Depends(require_admin_token)])
async def get_program_finding_report_alias(program_id: str, finding_id: str, format: str = Query("markdown", pattern="^(markdown|pdf|html|json)$")):
    return await get_finding_report(program_id, finding_id, format)

@router.get("/reports/program/{program_id}", dependencies=[Depends(require_admin_token)])
async def get_program_report_alias(
    program_id: str,
    format: str = Query("markdown", pattern="^(markdown|pdf|html|json)$"),
    profile: str = Query("auto", pattern="^(auto|bugcrowd|hackerone|redteam)$"),
):
    return await get_investigation_report(program_id, format, profile)
