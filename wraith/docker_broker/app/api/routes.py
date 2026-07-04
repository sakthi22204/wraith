from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from ..proxy import docker_proxy
from ..whitelist import ALLOWED_IMAGES

router = APIRouter()

@router.post("/containers")
async def create_container(spec: dict):
    return {"container_id": await docker_proxy.create_container(spec)}

@router.post("/containers/{container_id}/wait")
async def wait_container(container_id: str, timeout: Optional[int] = None):
    return await docker_proxy.wait_container(container_id, timeout)

@router.get("/containers/{container_id}/logs")
async def get_logs(container_id: str):
    return {"logs": await docker_proxy.get_logs(container_id)}

@router.post("/containers/{container_id}/stop")
async def stop_container(container_id: str):
    await docker_proxy.stop_container(container_id)
    return {"status": "stopped"}

@router.delete("/containers/{container_id}")
async def remove_container(container_id: str):
    await docker_proxy.remove_container(container_id)
    return {"status": "removed"}

@router.get("/whitelist")
async def get_whitelist():
    return {"allowed_images": ALLOWED_IMAGES}
