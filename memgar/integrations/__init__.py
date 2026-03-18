cat > /home/claude/memgar-main/memgar/integrations/__init__.py << 'EOF'
"""
Memgar Integrations
===================

Framework integrations for popular AI agent libraries.

Supported:
- LangChain: Memory wrappers
- LlamaIndex: Memory interceptors  
- MCP: Server middleware

Example:
    >>> from memgar.integrations.langchain import SecureMemory
    >>> memory = SecureMemory(ConversationBufferMemory())
"""

from memgar.integrations.langchain import SecureMemory, MemgarCallbackHandler
from memgar.integrations.mcp import MCPSecurityMiddleware

__all__ = [
    "SecureMemory",
    "MemgarCallbackHandler", 
    "MCPSecurityMiddleware",
]
EOF
echo "Fixed integrations/__init__.py"
