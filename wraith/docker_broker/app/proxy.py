import docker
import asyncio
import requests.exceptions
from typing import List, Optional
from .config import settings
from .validators import validate_container_spec, ALLOWED_SPEC_KEYS
from .audit import audit_log

class DockerProxy:
    def __init__(self):
        self._client = None

    @property
    def client(self):
        if self._client is None:
            self._client = docker.DockerClient(base_url=settings.DOCKER_SOCKET)
        return self._client

    async def create_container(self, spec: dict):
        # Spec can contain: image, command, mem_limit, cpu_quota, detach, remove, etc.
        try:
            validate_container_spec(spec)
            # Capture the image before run() pops it so the audit entry
            # always records the actual target (not "unknown").
            audit_image = spec.get("image")

            def run():
                # Extract image and command to call correctly
                image = spec.pop("image")
                command = spec.pop("command", None)

                # Ensure image is available locally
                try:
                    self.client.images.get(image)
                except docker.errors.ImageNotFound:
                    print(f"Image {image} not found locally, pulling...")
                    try:
                        self.client.images.pull(image)
                    except Exception as pull_err:
                        print(f"Failed to pull image {image}: {pull_err}")
                        raise pull_err

                # Forward only what the allowlist permits, by name.
                #
                # **spec used to hand every key the caller sent straight to the
                # Docker SDK, so the validator was the only thing standing
                # between a caller and mounts/volumes_from/cgroupns -- and it
                # had not heard of any of them. Selecting the keys here as well
                # means a key added to the SDK, or missed by the validator, is
                # dropped instead of executed: the run() call cannot be widened
                # by anything the validator does not already know about.
                forwarded = {k: v for k, v in spec.items() if k in ALLOWED_SPEC_KEYS}

                container = self.client.containers.run(
                    image=image,
                    command=command,
                    **forwarded,
                )
                return container.id

            container_id = await asyncio.to_thread(run)
            audit_log("CREATE", audit_image, True)
            return container_id
        except Exception as e:
            audit_log("CREATE", spec.get("image", "unknown"), False, getattr(e, "detail", str(e)))
            raise e

    async def wait_container(self, container_id: str, timeout: Optional[int] = None):
        """Wait for a container, bounded by ``timeout`` seconds.

        The Docker SDK's ``container.wait(timeout=...)`` does not actually bound
        the call -- the daemon-side /wait endpoint can block well past it, which
        leaves a long-running tool (nuclei over a widening route set) running
        until the caller's own HTTP timeout abandons it mid-write. A tool that
        is abandoned mid-run and then retried reports "0 findings" three passes
        later, so a pass that cannot fit its budget must be stopped cleanly at
        the deadline and have whatever it flushed returned -- partial evidence is
        still evidence. Poll instead: return as soon as the container exits, and
        stop it (SIGKILL) at the deadline so the caller gets an answer and does
        not retry a scan that only needed more time than it was allowed.
        """
        import time as _time

        deadline = _time.monotonic() + timeout if timeout else None

        def snapshot():
            container = self.client.containers.get(container_id)
            state = container.attrs["State"]
            return {"state": container, "status": state.get("Status"),
                    "code": state.get("ExitCode"), "oom": state.get("OOMKilled")}

        while True:
            try:
                snap = await asyncio.to_thread(snapshot)
            except docker.errors.NotFound:
                return {"StatusCode": 0, "Error": {"Message": "Container already removed"}}
            if snap["status"] in ("exited", "dead", "created"):
                code = snap["code"]
                if snap["oom"]:
                    return {"StatusCode": int(code or 137), "Error": {"Message": "OOM killed by the container runtime"}}
                return {"StatusCode": int(code or 0), "Error": None}
            if deadline and _time.monotonic() >= deadline:
                def stop():
                    snap["state"].stop(timeout=5)
                await asyncio.to_thread(stop)
                return {"StatusCode": -1, "Error": {"Message": "Pass exceeded its wall-clock budget; container stopped"}}
            await asyncio.sleep(2)

    async def get_logs(self, container_id: str):
        def run():
            try:
                container = self.client.containers.get(container_id)
                # tail-bounded: default logs() is tail="all" and buffers the whole
                # stream in memory, which OOM-killed this broker on verbose tools.
                return container.logs(tail=settings.LOG_TAIL_LINES).decode("utf-8", errors="replace")
            except docker.errors.NotFound:
                return ""
            except docker.errors.APIError as e:
                return f"Error fetching logs: {e}"
            except requests.exceptions.ConnectionError:
                return "Error fetching logs: Docker daemon connection lost"
        return await asyncio.to_thread(run)

    async def stop_container(self, container_id: str):
        def run():
            try:
                container = self.client.containers.get(container_id)
                container.stop()
            except docker.errors.NotFound:
                pass
            except docker.errors.APIError as e:
                print(f"Error stopping container {container_id}: {e}")
            except requests.exceptions.ConnectionError:
                print(f"Error stopping container {container_id}: Docker daemon connection lost")
        await asyncio.to_thread(run)

    async def remove_container(self, container_id: str):
        def run():
            try:
                container = self.client.containers.get(container_id)
                container.remove(force=True)
            except docker.errors.NotFound:
                pass
            except docker.errors.APIError as e:
                print(f"Error removing container {container_id}: {e}")
            except requests.exceptions.ConnectionError:
                print(f"Error removing container {container_id}: Docker daemon connection lost")
        await asyncio.to_thread(run)

docker_proxy = DockerProxy()
