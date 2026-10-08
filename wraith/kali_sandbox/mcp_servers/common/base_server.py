import asyncio
import re
import subprocess
import os
from typing import List, Optional
from urllib.parse import urlparse

from mcp.server.fastmcp import FastMCP

class BaseSecurityServer:
    def __init__(self, name: str):
        self.mcp = FastMCP(name)
        self.dangerous_tools = {"run_msf_module", "run_hydra"}
        self.authorized_callers = set(os.getenv("AUTHORIZED_DANGEROUS_CALLERS", "active_exploit_runner").split(","))
        # Basic validation: alphanumeric, dots, hyphens, colons (for ports/URLs)
        # No shell metacharacters like ; | & > < $ ( )
        self.target_regex = re.compile(r"^[a-zA-Z0-9\.\-\_\:\/]+$")

    def validate_target(self, target: str):
        if not self.target_regex.fullmatch(target):
            raise ValueError(f"Invalid target: {target}. Potential command injection detected.")

    # Characters that are never legal in a URL and are the ones that would make
    # a URL-shaped argument dangerous if a scanner shelled out downstream:
    # whitespace (command-line splitting, CRLF), shell quotes, redirection,
    # brace expansion, pipes, and command-substitution casing (`$(` `)` `$var`).
    # `$`, `(`, `)` are technically RFC-legal sub-delimiters, but they are the
    # exact spelling of shell casing and essentially never appear raw in an
    # HTTPS URL, so rejecting them costs real targets nothing while closing the
    # shell-out vector. Everything else up to 0x7F (including `?&=%#;[]*+,@!~`)
    # is admitted without having to enumerate the RFC character set.
    URL_BLOCKED_CHARS = frozenset(' \t\r\n"\'`\\<>{}|$()')
    URL_SCHEMES = ("http", "https")

    def validate_url(self, url: str):
        """Validate a full URL argument.

        Deliberately separate from `validate_target`: that family is for bare
        hosts (nmap, hydra, metasploit), where a query string is meaningless and
        its characters are rejected. Scanners take a full URL, and a URL carries
        an opaque query string by design -- `?id=1&x=2` is an ordinary target
        for sqlmap, ghauri or commix, and rejecting the characters that make it
        up would refuse real targets while claiming to validate them.
        """
        if not isinstance(url, str) or not url or url.strip() != url:
            raise ValueError(f"Invalid URL: {url}. Potential command injection detected.")
        if any(ch in url for ch in self.URL_BLOCKED_CHARS):
            raise ValueError(f"Invalid URL: {url}. Potential command injection detected.")
        try:
            parsed = urlparse(url)
        except ValueError as exc:
            raise ValueError(f"Invalid URL: {url}. Potential command injection detected.") from exc
        if (parsed.scheme or "").lower() not in self.URL_SCHEMES:
            raise ValueError(f"Invalid URL: {url}. Scheme must be http or https.")
        if not parsed.hostname:
            raise ValueError(f"Invalid URL: {url}. No host.")
        return url

    def split_host_port(self, target: str) -> tuple[str, Optional[str]]:
        host, sep, port = target.partition(":")
        return host, (port if sep else None)

    def verify_caller(self, tool_name: str, caller: Optional[str]):
        # All tools now require verification to be safe,
        # but only dangerous ones are restricted to a specific list.
        if tool_name in self.dangerous_tools:
            if caller not in self.authorized_callers:
                raise ValueError(f"Caller {caller} is not authorized to use {tool_name}")
        elif not caller:
             # Basic check: every tool call must identify a caller
             raise ValueError(f"Caller identity required for tool {tool_name}")

    @staticmethod
    def _result(
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        success: bool = False,
        error: Optional[str] = None,
    ) -> dict:
        """Every exit path returns this shape, so callers never have to guess.

        The failure paths used to omit stdout/stderr entirely, while the success
        path included them. Callers index res["stdout"] directly -- nmap, sqlmap,
        hydra and metasploit all do -- so a timeout or a missing binary raised
        KeyError inside the parser instead of reaching the error branch.

        That made the two most common operational failures unreportable: a hung
        scan surfaced as "KeyError: 'stdout'" rather than "Tool timed out", and a
        tool that was not installed on the image surfaced the same way. The
        information needed to say what went wrong was present in the return value
        and simply being dropped on the floor.
        """
        result = {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "success": success,
        }
        if error is not None:
            result["error"] = error
        return result

    async def run_tool(self, cmd: List[str], timeout: int = 300) -> dict:
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                return self._result(
                    stdout=stdout.decode(errors="replace"),
                    stderr=stderr.decode(errors="replace"),
                    exit_code=process.returncode,
                    success=process.returncode == 0,
                )
            except asyncio.TimeoutError:
                process.kill()
                # Reap the child. Without this it stays a zombie until the
                # event loop's own cleanup gets to it, so repeated timeouts
                # accumulate processes that are killed but never reaped.
                try:
                    await process.wait()
                except Exception:
                    pass
                return self._result(
                    exit_code=-1,
                    success=False,
                    error=f"Tool timed out after {timeout}s",
                )
        except Exception as e:
            # A missing binary is the common case here, and its message is the
            # only clue the operator gets, so it is preserved verbatim.
            return self._result(exit_code=-1, success=False, error=str(e))
