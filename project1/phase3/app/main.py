import uvicorn
from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.responses import HTMLResponse
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
# 引入 PublicKeyCredentialDescriptor 來解決 dict 無法讀取屬性的問題
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

app = FastAPI()

# 模擬資料庫 (記憶體儲存，伺服器重啟會清空)
# 資料結構: { "username": {"credential_id": bytes, "public_key": bytes, "sign_count": int, "challenge": bytes} }
db = {}

# WebAuthn 配置參數
RP_ID = "localhost"
RP_NAME = "Cryptography Project 1"
# 預設 ORIGIN，稍後會動態從 Request 中抓取以避免 127.0.0.1 與 localhost 不同的問題
DEFAULT_ORIGIN = "http://localhost:8000"

# --- 前端 HTML 介面 ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAuthn Phase 3 Demo</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .status-box { transition: all 0.2s ease-in-out; }
    </style>
</head>
<body class="bg-gray-50 min-h-screen flex items-center justify-center p-4">
    <div class="bg-white p-8 rounded-2xl shadow-xl w-full max-w-md border border-gray-100">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-extrabold text-gray-900 mb-2">Phase 3</h1>
            <p class="text-gray-500">WebAuthn 通行密鑰認證</p>
        </div>
        
        <div class="space-y-5">
            <div>
                <label class="block text-sm font-semibold text-gray-700 mb-2">Username</label>
                <input type="text" id="username" 
                    class="block w-full border border-gray-300 rounded-xl shadow-sm p-3.5 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition" 
                    placeholder="Enter your username">
            </div>
            
            <div class="grid grid-cols-1 gap-3">
                <button onclick="handleWebAuthn('register')" 
                    class="w-full bg-indigo-600 text-white font-bold py-3.5 rounded-xl hover:bg-indigo-700 active:scale-95 transition transform">
                    Register (Save Private Key)
                </button>
                
                <button onclick="handleWebAuthn('login')" 
                    class="w-full bg-emerald-600 text-white font-bold py-3.5 rounded-xl hover:bg-emerald-700 active:scale-95 transition transform">
                    Login (Sign Challenge)
                </button>
            </div>
        </div>

        <div id="statusBox" class="mt-8 p-4 rounded-xl hidden status-box border">
            <p id="statusMessage" class="text-sm font-medium leading-relaxed"></p>
        </div>
    </div>

    <script>
        // 工具：將 Base64URL 字串與 ArrayBuffer 互相轉換 (WebAuthn API 規定格式)
        const bufferDecode = (value) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
        const bufferEncode = (value) => btoa(String.fromCharCode.apply(null, new Uint8Array(value))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

        function showStatus(msg, isError = false) {
            const box = document.getElementById('statusBox');
            const text = document.getElementById('statusMessage');
            
            box.className = "mt-8 p-4 rounded-xl status-box border " + 
                (isError ? "bg-red-50 border-red-200 text-red-800" : "bg-green-50 border-green-200 text-green-800");
            
            text.innerText = msg;
            box.classList.remove('hidden');
        }

        async function handleWebAuthn(action) {
            const username = document.getElementById('username').value.trim();
            if (!username) { 
                showStatus("Please enter a username first.", true);
                return; 
            }

            try {
                // 1. 向後端請求 Challenge 與配置選項
                const startRes = await fetch(`/${action}/begin?username=${username}`, { method: 'POST' });
                
                if (!startRes.ok) {
                    const errorData = await startRes.json();
                    throw new Error(errorData.detail);
                }

                const options = await startRes.json();

                // 2. 轉換資料格式以符合瀏覽器原生 WebAuthn API 要求
                options.challenge = bufferDecode(options.challenge);

                if (action === 'register') {
                    options.user.id = bufferDecode(options.user.id);
                    const credential = await navigator.credentials.create({ publicKey: options });
                    
                    const responseBody = {
                        id: credential.id,
                        rawId: bufferEncode(credential.rawId),
                        type: credential.type,
                        response: {
                            attestationObject: bufferEncode(credential.response.attestationObject),
                            clientDataJSON: bufferEncode(credential.response.clientDataJSON),
                        }
                    };

                    const finish = await fetch(`/register/complete?username=${username}`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(responseBody)
                    });
                    
                    const resJson = await finish.json();
                    if (!finish.ok) throw new Error(resJson.detail || "Registration failed");
                    
                    showStatus("Registration successful! Private key saved.");
                    
                } else {
                    options.allowCredentials.forEach(c => c.id = bufferDecode(c.id));
                    const assertion = await navigator.credentials.get({ publicKey: options });

                    const responseBody = {
                        id: assertion.id,
                        rawId: bufferEncode(assertion.rawId),
                        type: assertion.type,
                        response: {
                            authenticatorData: bufferEncode(assertion.response.authenticatorData),
                            clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
                            signature: bufferEncode(assertion.response.signature),
                            userHandle: assertion.response.userHandle ? bufferEncode(assertion.response.userHandle) : null,
                        }
                    };

                    const finish = await fetch(`/login/complete?username=${username}`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify(responseBody)
                    });
                    
                    const resJson = await finish.json();
                    if (!finish.ok) throw new Error(resJson.detail || "Login failed");
                    
                    showStatus("Login successful! Challenge verified.");
                }

            } catch (err) {
                // 作業規範：處理使用者按下「取消」的情境
                if (err.name === 'NotAllowedError') {
                    const cancelMsg = action === 'register' 
                        ? 'The "save private key" process is canceled during registration.' 
                        : 'The validation process is canceled during login.';
                    showStatus(cancelMsg, true);
                } else {
                    showStatus(err.message, true);
                }
            }
        }
    </script>
</body>
</html>
"""

# --- 後端 API 實作 ---

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    return HTML_TEMPLATE

@app.post("/register/begin")
async def register_begin(username: str):
    # Scenario 1: 確保使用者不存在，或者還沒「完成」註冊
    if username in db and "credential_id" in db[username]:
        raise HTTPException(
            status_code=400, 
            detail="The user tries to register with a username that is already registered."
        )
    
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=username.encode("utf-8"), 
        user_name=username,
    )
    # 建立暫存的挑戰碼
    db[username] = {"challenge": options.challenge}
    return Response(content=options_to_json(options), media_type="application/json")

@app.post("/register/complete")
async def register_complete(username: str, credential: dict, request: Request):
    if username not in db or "challenge" not in db[username]:
        raise HTTPException(status_code=400, detail="Registration session not found.")
    
    # 動態獲取來源，解決 127.0.0.1 與 localhost 不同的問題
    client_origin = request.headers.get("origin", DEFAULT_ORIGIN)
    
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=db[username]["challenge"],
            expected_origin=client_origin,
            expected_rp_id=RP_ID,
        )
        # 真正完成註冊，寫入公鑰與憑證ID
        db[username]["credential_id"] = verification.credential_id
        # 新版 webauthn 屬性名稱改為 credential_public_key
        db[username]["public_key"] = verification.credential_public_key
        db[username]["sign_count"] = verification.sign_count
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/login/begin")
async def login_begin(username: str):
    # Scenario 2: 必須檢查 credential_id 是否存在（確保已經完成註冊流程）
    if username not in db or "credential_id" not in db[username]:
        raise HTTPException(
            status_code=400, 
            detail="The user tries to log in with a username that is not registered."
        )
    
    options = generate_authentication_options(
        rp_id=RP_ID,
        # 使用 PublicKeyCredentialDescriptor 取代普通的 dict
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=db[username]["credential_id"])
        ],
    )
    db[username]["login_challenge"] = options.challenge
    return Response(content=options_to_json(options), media_type="application/json")

@app.post("/login/complete")
async def login_complete(username: str, credential: dict, request: Request):
    if username not in db or "login_challenge" not in db[username]:
        raise HTTPException(status_code=400, detail="Login session not found.")

    client_origin = request.headers.get("origin", DEFAULT_ORIGIN)

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=db[username]["login_challenge"],
            expected_origin=client_origin,
            expected_rp_id=RP_ID,
            credential_public_key=db[username]["public_key"],
            credential_current_sign_count=db[username]["sign_count"],
        )
        db[username]["sign_count"] = verification.new_sign_count
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)