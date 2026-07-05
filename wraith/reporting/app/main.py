from fastapi import FastAPI
from .api.routes import router

app = FastAPI(title="Wraith Reporting Service")

app.include_router(router)

@app.get("/health")
async def health():
    return {"status": "healthy"}
