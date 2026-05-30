from __future__ import annotations

import subprocess
import tempfile
import webbrowser
from dataclasses import asdict
from pathlib import Path
from threading import Timer

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

from pqc_audit.config import AppConfig
from pqc_audit.pipeline import AuditPipeline


PROJECT_ROOT = Path(__file__).resolve().parent
INDEX_HTML = PROJECT_ROOT / "index.html"

app = FastAPI(title="PQC Audit Web UI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    repo_url: str


@app.get("/")
async def serve_root() -> FileResponse:
    return await serve_index()


@app.get("/index.html")
async def serve_index() -> FileResponse:
    if not INDEX_HTML.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(INDEX_HTML)


@app.post("/api/scan")
async def scan_repo(request: ScanRequest) -> dict:
    repo_url = request.repo_url.strip()
    if not repo_url:
        raise HTTPException(status_code=400, detail="Repository URL is required")
    if not repo_url.endswith(".git"):
        raise HTTPException(status_code=400, detail="Please input a Git clone URL ending with .git")

    with tempfile.TemporaryDirectory(prefix="pqc-audit-") as temp_dir:
        workspace = Path(temp_dir)
        repo_dir = workspace / "repo"
        report_dir = workspace / "reports"

        _clone_repository(repo_url, repo_dir)

        config = AppConfig(
            target_path=repo_dir,
            output_dir=report_dir,
            report_format="json",
            skip_ai=True,
        )
        report = AuditPipeline().run(config)
        response = asdict(report)
        response["target_path"] = repo_url
        return response


def _clone_repository(repo_url: str, repo_dir: Path) -> None:
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(repo_dir)],
            cwd=PROJECT_ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="Git clone timed out") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise HTTPException(status_code=500, detail=f"Git clone failed: {detail}") from exc


def open_browser() -> None:
    webbrowser.open("http://localhost:8000/index.html")


if __name__ == "__main__":
    Timer(1, open_browser).start()
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
