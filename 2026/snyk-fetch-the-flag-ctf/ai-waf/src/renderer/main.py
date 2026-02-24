import time
import uuid
import random
from datetime import datetime

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jinja2 import Template

app = FastAPI()

def render_content(raw: str) -> str:
    try:
        tmpl = Template(raw)
        now = datetime.utcnow()
        ctx = {
            "date": now.strftime("%Y-%m-%d"),
            "time": now.strftime("%H:%M:%S"),
            "now": now.isoformat() + "Z",
            "timestamp": str(time.time()),
            "uuid": str(uuid.uuid4()),
            "random_int": str(random.randint(1, 1000)),
        }
        return tmpl.render(**ctx)
    except Exception as e:
        return raw

@app.post("/internal/render", response_class=JSONResponse)
async def render_task_internal(request: Request):
    content = ""
    try:
        data = await request.json()
        content = data.get("content", "")
    except Exception:
        pass
    
    rendered = render_content(content)
    return JSONResponse({"rendered": rendered})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
