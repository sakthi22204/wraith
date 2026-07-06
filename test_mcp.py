from mcp.server.fastmcp import FastMCP
mcp = FastMCP("test")
@mcp.custom_route("/test", methods=["GET"])
async def test_route(request):
    return {"ok": True}
print("Success")
