from fastapi import FastAPI
from .api.routes import router

app = FastAPI(title="Wraith Docker Broker")

app.include_router(router, prefix="/api/v1")

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)
