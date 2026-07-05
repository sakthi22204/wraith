from fastapi import APIRouter, HTTPException, Query, Response
from ..generator import generator
from ..pdf_export import pdf_exporter
from ..clients.graph_db_client import graph_db_client
from jinja2 import Environment, FileSystemLoader
from datetime import datetime
import os

router = APIRouter()

template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
env = Environment(loader=FileSystemLoader(template_dir))

def parse_date(ts):
    if not ts: return datetime.utcnow()
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except:
        return datetime.utcnow()

@router.get("/reports/{program_id}/findings/{finding_id}")
async def get_finding_report(program_id: str, finding_id: str, format: str = Query("markdown", pattern="^(markdown|pdf)$")):
    # Need to fetch the specific finding
    all_findings = await graph_db_client.get_findings_for_program(program_id)
    finding = next((f for f in all_findings if f["id"] == finding_id), None)

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    report_finding = await generator.generate_finding_report(program_id, finding)
    program_data = await graph_db_client.get_program(program_id)

    report_data = {
        "program_name": program_data.get("name", "Unknown") if program_data else "Unknown",
        "generated_at": parse_date(report_finding.discovery_metadata["timestamp"]),
        "findings": [report_finding]
    }

    if format == "pdf":
        pdf_bytes = pdf_exporter.export_report(report_data)
        return Response(content=pdf_bytes, media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=finding_{finding_id}.pdf"
        })
    else:
        template = env.get_template("finding_report.md.j2")
        md_out = template.render(**report_data)
        return Response(content=md_out, media_type="text/markdown")

@router.get("/reports/{program_id}")
async def get_program_report(program_id: str, format: str = Query("markdown", pattern="^(markdown|pdf)$")):
    report = await generator.generate_program_report(program_id)
    report_data = report.model_dump()

    if format == "pdf":
        pdf_bytes = pdf_exporter.export_report(report_data)
        return Response(content=pdf_bytes, media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=program_{program_id}.pdf"
        })
    else:
        template = env.get_template("finding_report.md.j2")
        md_out = template.render(**report_data)
        return Response(content=md_out, media_type="text/markdown")
