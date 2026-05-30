import os
import json
import subprocess
import tempfile
import webbrowser

from threading import Timer

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel

import uvicorn

import platform
import subprocess

app = FastAPI()

# 自動開啟瀏覽器

def open_browser():
    url = "http://127.0.0.1:8000"

    # Windows
    if platform.system() == "Windows":
        os.startfile(url)

    # WSL
    elif "microsoft" in platform.uname().release.lower():
        subprocess.run(["cmd.exe", "/c", "start", url])

    # Linux desktop
    else:
        try:
            webbrowser.open(url)
        except Exception:
            print(f"Open browser manually: {url}")


# 提供 index.html
@app.get("/")
async def serve_index():
    return FileResponse("index.html")


# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 前端 request 格式
class ScanRequest(BaseModel):
    repo_url: str


@app.post("/api/scan")
async def scan_repo(request: ScanRequest):
    repo_url = request.repo_url

    with tempfile.TemporaryDirectory() as temp_dir:
        repo_dir = os.path.join(temp_dir, "repo")
        report_dir = os.path.join(temp_dir, "reports")

        os.makedirs(report_dir, exist_ok=True)

        try:
            # clone repo
            subprocess.run(
                ["git", "clone", repo_url, repo_dir],
                check=True,
                capture_output=True,
                text=True
            )

            # 執行 pqc-audit
            subprocess.run(
                [
                    "uv",
                    "run",
                    "pqc-audit",
                    "--target",
                    repo_dir,
                    "--output",
                    report_dir,
                    "--format",
                    "json",
                ],
                check=True,
                capture_output=True,
                text=True
            )

            # 讀取 JSON
            json_file_path = os.path.join(
                report_dir,
                "security-report.json"
            )

            if not os.path.exists(json_file_path):
                raise HTTPException(
                    status_code=500,
                    detail="找不到 security-report.json"
                )

            with open(json_file_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)

            return report_data

        except subprocess.CalledProcessError as e:
            error_msg = e.stderr if e.stderr else str(e)

            print("Error occurred:")
            print(error_msg)

            raise HTTPException(
                status_code=500,
                detail=f"系統執行失敗:\n{error_msg}"
            )


# 一鍵啟動
if __name__ == "__main__":
    Timer(1, open_browser).start()

    uvicorn.run(
        "server:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )