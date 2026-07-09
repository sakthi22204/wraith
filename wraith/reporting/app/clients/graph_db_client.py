import httpx
from ..config import settings

class GraphDBClient:
    def __init__(self, base_url: str = settings.GRAPH_DB_URL):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}

    async def get_program(self, program_id: str):
        async with httpx.AsyncClient(headers=self.headers) as client:
            response = await client.get(f"{self.base_url}/programs/{program_id}/graph")
            response.raise_for_status()
            # The graph endpoint returns program in the 'nodes' or as a separate 'p' property
            # For simplicity, we assume we can fetch it or derive from nodes
            data = response.json()
            # Program node usually has 'Program' label
            for node in data.get("nodes", []):
                if "Program" in node.get("labels", []):
                    return node.get("properties")
            return None

    async def get_finding(self, program_id: str, finding_id: str):
        async with httpx.AsyncClient(headers=self.headers) as client:
            response = await client.get(f"{self.base_url}/programs/{program_id}/findings")
            response.raise_for_status()
            findings = response.json()
            return next((f for f in findings if f["id"] == finding_id), None)

    async def get_findings_for_program(self, program_id: str):
        async with httpx.AsyncClient(headers=self.headers) as client:
            response = await client.get(f"{self.base_url}/programs/{program_id}/findings")
            response.raise_for_status()
            return response.json()

    async def get_target_details(self, program_id: str, target_id: str):
        async with httpx.AsyncClient(headers=self.headers) as client:
            response = await client.get(f"{self.base_url}/programs/{program_id}/graph")
            response.raise_for_status()
            data = response.json()

            target_node = None
            for node in data.get("nodes", []):
                if node["id"] == target_id:
                    target_node = node
                    break

            if not target_node:
                return None

            details = {"id": target_id, "labels": target_node["labels"], "properties": target_node["properties"]}

            # Find parent host for context
            host_node = None
            if "Host" in target_node["labels"]:
                host_node = target_node
            else:
                # Walk back to Host
                curr_id = target_id
                found_host = False
                while not found_host:
                    parent_id = None
                    for link in data.get("links", []):
                        if link["target"] == curr_id:
                            parent_id = link["source"]
                            break
                    if not parent_id:
                        break
                    for node in data.get("nodes", []):
                        if node["id"] == parent_id:
                            if "Host" in node["labels"]:
                                host_node = node
                                found_host = True
                            curr_id = parent_id
                            break
                    if not parent_id: break

            if host_node:
                details["host"] = host_node["properties"].get("value")

            return details

    async def get_discovering_tool(self, program_id: str, finding_id: str):
        async with httpx.AsyncClient(headers=self.headers) as client:
            response = await client.get(f"{self.base_url}/programs/{program_id}/graph")
            response.raise_for_status()
            data = response.json()

            for link in data.get("links", []):
                if link["source"] == finding_id and link["type"] == "DISCOVERED_BY":
                    tool_id = link["target"]
                    for node in data.get("nodes", []):
                        if node["id"] == tool_id:
                            return node["properties"]
            return None

graph_db_client = GraphDBClient()
