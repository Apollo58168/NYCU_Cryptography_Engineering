import os
import json
import subprocess
import tempfile
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

# 【重要】允許前端跨網域連線 (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 開放所有來源，方便本地開發測試
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 定義前端傳來的資料格式
class ScanRequest(BaseModel):
    repo_url: str

@app.post("/api/scan")
async def scan_repo(request: ScanRequest):
    repo_url = request.repo_url
    
    # 建立一個暫存資料夾來放 Clone 下來的程式碼與報告
    with tempfile.TemporaryDirectory() as temp_dir:
        repo_dir = os.path.join(temp_dir, "repo")
        report_dir = os.path.join(temp_dir, "reports")
        os.makedirs(report_dir, exist_ok=True)
        
        try:
            # 1. 執行 git clone
            subprocess.run(
                ["git", "clone", repo_url, repo_dir], 
                check=True, 
                capture_output=True
            )
            
            # 2. 執行你的 pqc-audit CLI 工具 (指定 target 為剛 clone 的資料夾，output 為暫存報告區)
            # 注意：這裡預設使用 AI，確保 .env 的 GEMINI_API_KEY 已設定好
            subprocess.run(
                [
                    "uv", "run", "pqc-audit", 
                    "--target", repo_dir, 
                    "--output", report_dir, 
                    "--format", "json"
                ],
                check=True,
                capture_output=True
            )
            
            # 3. 讀取產出的 security-report.json
            json_file_path = os.path.join(report_dir, "security-report.json")
            if not os.path.exists(json_file_path):
                raise HTTPException(status_code=500, detail="報告生成失敗，找不到 JSON 檔案")
                
            with open(json_file_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)
                
            # 4. 將 JSON 資料回傳給前端
            return report_data
            
        except subprocess.CalledProcessError as e:
            # 如果執行指令失敗，印出錯誤訊息方便 debug
            error_msg = e.stderr.decode('utf-8') if e.stderr else str(e)
            print(f"Error occurred: {error_msg}")
            raise HTTPException(status_code=500, detail=f"系統執行失敗: {error_msg}")