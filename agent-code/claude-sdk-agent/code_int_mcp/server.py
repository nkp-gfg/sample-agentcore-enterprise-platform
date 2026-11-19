# Adapted from fullstack-solution-template-for-agentcore
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""In-process MCP server for Code Interpreter.

The sandbox session is chosen by ``client`` from the caller the entrypoint
bound with ``client.bind_caller``. Tool arguments never select it, so any
session id the model supplies is ignored.
"""

import json
import logging
from typing import Any

from claude_agent_sdk import create_sdk_mcp_server, tool

from .client import CodeInterpreterClient

logger = logging.getLogger(__name__)

client = CodeInterpreterClient()


@tool(
    "execute_code",
    "Execute code using Code Interpreter.",
    {"code": str, "language": str},
)
async def execute_code(args: dict[str, Any]) -> dict[str, Any]:
    result = client.execute_code(
        args.get("code"),
        args.get("language", "python"),
    )
    response_text = result.model_dump_json(indent=2)

    return {"content": [{"type": "text", "text": response_text}]}


@tool(
    "execute_command",
    "Execute command using Code Interpreter.",
    {"command": str},
)
async def execute_command(args: dict[str, Any]) -> dict[str, Any]:
    result = client.execute_command(args.get("command"))
    response_text = result.model_dump_json(indent=2)

    return {"content": [{"type": "text", "text": response_text}]}


@tool(
    "write_files",
    "Write files using Code Interpreter.",
    {"files_to_create": list},
)
async def write_files(args: dict[str, Any]) -> dict[str, Any]:
    files_to_create = args["files_to_create"]
    if isinstance(files_to_create, str):
        files_to_create = json.loads(files_to_create)

    result = client.write_files(files_to_create)
    response_text = result.model_dump_json(indent=2)

    return {"content": [{"type": "text", "text": response_text}]}


@tool(
    "read_files",
    "Read files using Code Interpreter.",
    {"paths": list},
)
async def read_files(args: dict[str, Any]) -> dict[str, Any]:
    paths = args["paths"]
    if isinstance(paths, str):
        paths = json.loads(paths)
    result = client.read_files(paths)
    response_text = result.model_dump_json(indent=2)

    return {"content": [{"type": "text", "text": response_text}]}


code_int_mcp_server = create_sdk_mcp_server(
    name="codeinterpretertools",
    version="1.0.0",
    tools=[execute_code, execute_command, write_files, read_files],
)
