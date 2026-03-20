"""
Memgar MCP Server
=================

Model Context Protocol server for Claude Desktop integration.

This allows Claude to use Memgar as a tool for scanning
AI agent memories directly from the Claude interface.

Usage:
    # Run as MCP server
    python -m memgar.integrations.mcp_server
    
    # Or use the CLI
    memgar mcp-server --port 8080

Configuration (claude_desktop_config.json):
    {
      "mcpServers": {
        "memgar": {
          "command": "python",
          "args": ["-m", "memgar.integrations.mcp_server"]
        }
      }
    }
"""

import json
import sys
import asyncio
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict
import logging

from ..scanner import MemoryScanner
from ..models import Decision
from ..patterns import PATTERNS, pattern_stats, get_pattern_by_id

logger = logging.getLogger(__name__)


@dataclass
class MCPTool:
    """MCP Tool definition."""
    name: str
    description: str
    input_schema: Dict[str, Any]


@dataclass
class MCPResponse:
    """MCP Response."""
    content: List[Dict[str, Any]]
    is_error: bool = False


class MemgarMCPServer:
    """
    MCP Server for Memgar.
    
    Provides tools for Claude to scan AI agent memories.
    
    Tools:
        - memgar_scan: Scan single memory entry
        - memgar_scan_batch: Scan multiple entries
        - memgar_patterns: List threat patterns
        - memgar_stats: Get pattern statistics
    """
    
    def __init__(self, mode: str = "protect"):
        """
        Initialize MCP server.
        
        Args:
            mode: Scan mode (protect, monitor, audit)
        """
        self._scanner = MemoryScanner(mode=mode)
        self._tools = self._define_tools()
    
    def _define_tools(self) -> List[MCPTool]:
        """Define available MCP tools."""
        return [
            MCPTool(
                name="memgar_scan",
                description="Scan a single AI agent memory entry for threats. Returns decision (ALLOW/BLOCK/QUARANTINE), risk score, and threat details.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "The memory content to scan for threats"
                        }
                    },
                    "required": ["content"]
                }
            ),
            MCPTool(
                name="memgar_scan_batch",
                description="Scan multiple AI agent memory entries at once. Returns summary statistics and individual results.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "contents": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of memory contents to scan"
                        }
                    },
                    "required": ["contents"]
                }
            ),
            MCPTool(
                name="memgar_patterns",
                description="List available threat patterns. Optionally filter by category or severity.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "description": "Filter by category (e.g., FINANCIAL, CREDENTIAL, PRIVILEGE)",
                            "enum": ["FINANCIAL", "CREDENTIAL", "PRIVILEGE", "EXFILTRATION", 
                                    "BEHAVIOR", "SLEEPER", "EVASION", "MANIPULATION", 
                                    "EXECUTION", "ANOMALY", "SOCIAL", "SUPPLY", 
                                    "INJECTION", "DATA"]
                        },
                        "severity": {
                            "type": "string",
                            "description": "Filter by severity level",
                            "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of patterns to return",
                            "default": 10
                        }
                    }
                }
            ),
            MCPTool(
                name="memgar_stats",
                description="Get Memgar pattern statistics including total patterns, counts by severity and category.",
                input_schema={
                    "type": "object",
                    "properties": {}
                }
            ),
            MCPTool(
                name="memgar_check_threat",
                description="Get details about a specific threat pattern by ID.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "threat_id": {
                            "type": "string",
                            "description": "Threat ID (e.g., FIN-001, CRED-002)"
                        }
                    },
                    "required": ["threat_id"]
                }
            ),
        ]
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Get tool definitions for MCP."""
        return [
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema
            }
            for tool in self._tools
        ]
    
    def handle_tool(self, name: str, arguments: Dict[str, Any]) -> MCPResponse:
        """
        Handle tool invocation.
        
        Args:
            name: Tool name
            arguments: Tool arguments
            
        Returns:
            MCPResponse with results
        """
        try:
            if name == "memgar_scan":
                return self._handle_scan(arguments)
            elif name == "memgar_scan_batch":
                return self._handle_scan_batch(arguments)
            elif name == "memgar_patterns":
                return self._handle_patterns(arguments)
            elif name == "memgar_stats":
                return self._handle_stats(arguments)
            elif name == "memgar_check_threat":
                return self._handle_check_threat(arguments)
            else:
                return MCPResponse(
                    content=[{"type": "text", "text": f"Unknown tool: {name}"}],
                    is_error=True
                )
        except Exception as e:
            return MCPResponse(
                content=[{"type": "text", "text": f"Error: {str(e)}"}],
                is_error=True
            )
    
    def _handle_scan(self, args: Dict[str, Any]) -> MCPResponse:
        """Handle memgar_scan tool."""
        content = args.get("content", "")
        result = self._scanner.scan(content)
        
        response_text = f"""## Memgar Scan Result

**Decision:** {result.decision.value}
**Risk Score:** {result.risk_score}/100

"""
        if result.threat_type:
            response_text += f"""**Threat ID:** {result.threat_type}
**Threat Name:** {result.threat_name}
**Category:** {result.category}
**Severity:** {result.severity}

**Explanation:** {result.explanation}
"""
        else:
            response_text += "✅ No threats detected. Content is safe."
        
        return MCPResponse(
            content=[{"type": "text", "text": response_text}]
        )
    
    def _handle_scan_batch(self, args: Dict[str, Any]) -> MCPResponse:
        """Handle memgar_scan_batch tool."""
        contents = args.get("contents", [])
        batch_result = self._scanner.scan_batch(contents)
        
        response_text = f"""## Memgar Batch Scan Results

**Total Scanned:** {batch_result.total}
**Allowed:** {batch_result.allowed} ✅
**Quarantined:** {batch_result.quarantined} ⚠️
**Blocked:** {batch_result.blocked} 🚫

### Details:
"""
        for i, result in enumerate(batch_result.results):
            status = "✅" if result.decision == Decision.ALLOW else "🚫" if result.decision == Decision.BLOCK else "⚠️"
            preview = contents[i][:50] + "..." if len(contents[i]) > 50 else contents[i]
            threat_info = f" ({result.threat_type})" if result.threat_type else ""
            response_text += f"{i+1}. {status} {preview}{threat_info}\n"
        
        return MCPResponse(
            content=[{"type": "text", "text": response_text}]
        )
    
    def _handle_patterns(self, args: Dict[str, Any]) -> MCPResponse:
        """Handle memgar_patterns tool."""
        category = args.get("category")
        severity = args.get("severity")
        limit = args.get("limit", 10)
        
        patterns = PATTERNS
        
        if category:
            patterns = [p for p in patterns if p.category.name == category]
        if severity:
            patterns = [p for p in patterns if p.severity.name == severity]
        
        patterns = patterns[:limit]
        
        response_text = f"""## Memgar Threat Patterns

**Showing:** {len(patterns)} patterns
"""
        if category:
            response_text += f"**Category Filter:** {category}\n"
        if severity:
            response_text += f"**Severity Filter:** {severity}\n"
        
        response_text += "\n| ID | Name | Severity | Description |\n|---|---|---|---|\n"
        
        for p in patterns:
            desc = p.description[:40] + "..." if len(p.description) > 40 else p.description
            response_text += f"| {p.id} | {p.name} | {p.severity.name} | {desc} |\n"
        
        return MCPResponse(
            content=[{"type": "text", "text": response_text}]
        )
    
    def _handle_stats(self, args: Dict[str, Any]) -> MCPResponse:
        """Handle memgar_stats tool."""
        stats = pattern_stats()
        
        response_text = f"""## Memgar Statistics

**Total Patterns:** {stats['total']}
**Categories:** {stats['categories']}

### By Severity:
- 🔴 CRITICAL: {stats['critical']}
- 🟠 HIGH: {stats['high']}
- 🟡 MEDIUM: {stats['medium']}
- 🟢 LOW: {stats['low']}

### Categories:
"""
        # Count by category
        cat_counts = {}
        for p in PATTERNS:
            cat = p.category.name
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
        
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
            response_text += f"- {cat}: {count}\n"
        
        return MCPResponse(
            content=[{"type": "text", "text": response_text}]
        )
    
    def _handle_check_threat(self, args: Dict[str, Any]) -> MCPResponse:
        """Handle memgar_check_threat tool."""
        threat_id = args.get("threat_id", "")
        threat = get_pattern_by_id(threat_id)
        
        if not threat:
            return MCPResponse(
                content=[{"type": "text", "text": f"❌ Threat ID not found: {threat_id}"}],
                is_error=True
            )
        
        response_text = f"""## Threat Details: {threat.id}

**Name:** {threat.name}
**Category:** {threat.category.name}
**Severity:** {threat.severity.name}

**Description:**
{threat.description}

**Keywords:** {', '.join(threat.keywords[:5])}

**Examples:**
"""
        for ex in threat.examples[:3]:
            response_text += f"- {ex}\n"
        
        if threat.mitre_attack:
            response_text += f"\n**MITRE ATT&CK:** {threat.mitre_attack}"
        
        return MCPResponse(
            content=[{"type": "text", "text": response_text}]
        )


def run_stdio_server():
    """Run MCP server over stdio."""
    server = MemgarMCPServer()
    
    # MCP protocol handlers
    def handle_request(request: Dict[str, Any]) -> Dict[str, Any]:
        method = request.get("method", "")
        params = request.get("params", {})
        request_id = request.get("id")
        
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "memgar",
                        "version": "0.2.0"
                    }
                }
            }
        
        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": server.get_tools()
                }
            }
        
        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})
            response = server.handle_tool(tool_name, tool_args)
            
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": response.content,
                    "isError": response.is_error
                }
            }
        
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }
    
    # Main loop
    logger.info("Memgar MCP Server starting...")
    
    for line in sys.stdin:
        try:
            request = json.loads(line)
            response = handle_request(request)
            print(json.dumps(response), flush=True)
        except json.JSONDecodeError:
            continue
        except Exception as e:
            logger.error(f"Error: {e}")


if __name__ == "__main__":
    run_stdio_server()
