from fastapi import FastAPI
from .api.routes import router

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Wraith Docker Broker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")

import docker
from .whitelist import ALLOWED_IMAGES

@app.on_event("startup")
async def startup_event():
    # Pre-pull images to ensure they are available
    client = docker.from_env()
    for image in ALLOWED_IMAGES:
        try:
            print(f"Checking for image {image}...")
            client.images.get(image)
        except docker.errors.ImageNotFound:
            print(f"Pre-pulling image {image}...")
            try:
                client.images.pull(image)
            except Exception as e:
                print(f"Failed to pre-pull {image}: {e}")

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)
