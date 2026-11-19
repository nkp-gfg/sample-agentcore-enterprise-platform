# Adapted from fullstack-solution-template-for-agentcore
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Subagent definitions for the Claude Agent SDK pattern.

Defines specialized subagents that the main agent can spawn via the Task tool.
Subagents run as separate claude-code child processes launched by the parent
claude-code process. They inherit MCP server configuration from the parent
ClaudeAgentOptions.
"""

from claude_agent_sdk import AgentDefinition


def get_subagent_definitions(mcp_servers: dict) -> dict[str, AgentDefinition]:
    """Build subagent definitions for task delegation.

    Args:
        mcp_servers: Dictionary of MCP server configurations.

    Returns:
        Dictionary mapping subagent names to their AgentDefinition configurations.
    """
    return {
        "code-analyst": AgentDefinition(
            description="Analyzes code output, debugs errors, and explains results. Can execute code via Code Interpreter. Use when you have code execution output or errors that need detailed analysis. Pass the output/error text directly in the task prompt.",
            prompt="""You are a code analysis specialist. You receive code, execution output, and error messages for analysis.

When analyzing:
- Identify root causes of errors
- Provide clear, actionable explanations
- Suggest fixes with code examples
- Use mcp__codeint__execute_code to test fixes if needed
- Summarize findings concisely

SESSION MANAGEMENT:
The Code Interpreter sandbox for this conversation is managed automatically. Do not pass a session ID to Code Interpreter tools.""",
            tools=[
                "mcp__codeint__execute_code",
                "mcp__codeint__execute_command",
                "mcp__gateway__*",
                "Read",
                "Grep",
                "Glob",
            ],
            model="sonnet",
        ),
    }
