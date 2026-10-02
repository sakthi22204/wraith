from fastapi import FastAPI
from .api.routes import router
from .config import settings, validate_startup_secrets

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Wraith Reporting Service")


@app.on_event("startup")
def startup_event():
    # Report generation reads the graph and can drive the runner, so a blank or
    # published admin token is not a degraded mode here.
    validate_startup_secrets(settings)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "healthy"}
