from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

router = APIRouter()

env = Environment(
    loader=FileSystemLoader("app/templates"),
    autoescape=select_autoescape(["html", "xml"]),
    cache_size=0,
)

def render_template(name: str, context: dict) -> str:
    template = env.get_template(name)
    return template.render(**context)

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    html = render_template("dashboard.html", {"request": request})
    return HTMLResponse(content=html)

@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: str):
    html = render_template("scan_detail.html", {"request": request, "scan_id": scan_id})
    return HTMLResponse(content=html)
