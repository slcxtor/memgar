"""
Memgar AutoGen Integration
==========================

Memory security for Microsoft AutoGen multi-agent systems.

Usage:
    from autogen import AssistantAgent, UserProxyAgent
    from memgar.integrations.autogen import MemgarAutoGenGuard, secure_agent
    
    # Wrap agents
    assistant = AssistantAgent("assistant", llm_config=config)
    secure_assistant = secure_agent(assistant)
    
    # Or use guard for conversations
    guard = MemgarAutoGenGuard()
    guard.monitor_conversation([assistant, user_proxy])
"""

from typing import Any, Dict, List, Optional, Callable, Union
from dataclasses import dataclass, field
import logging
import functools

from ..scanner import MemoryScanner
from ..models import Decision, AnalysisResult

logger = logging.getLogger(__name__)


@dataclass
class ConversationScanResult:
    """Result of conversation message scan."""
    sender: str
    receiver: str
    allowed: bool
    decision: str
    risk_score: int
    threat_type: Optional[str] = None
    content_preview: str = ""


@dataclass
class AutoGenScanStats:
    """Statistics for AutoGen scanning."""
    messages_scanned: int = 0
    threats_blocked: int = 0
    agents_monitored: int = 0
    conversations: int = 0


class MemgarAutoGenGuard:
    """
    Security guard for AutoGen multi-agent conversations.
    
    Monitors all agent communications for memory poisoning attacks.
    
    Example:
        from autogen import AssistantAgent, UserProxyAgent, GroupChat
        from memgar.integrations.autogen import MemgarAutoGenGuard
        
        assistant = AssistantAgent("assistant", llm_config=config)
        user = UserProxyAgent("user")
        
        guard = MemgarAutoGenGuard(on_threat="block")
        guard.secure_agents([assistant, user])
        
        # Start chat
        user.initiate_chat(assistant, message="Hello!")
    """
    
    def __init__(
        self,
        mode: str = "protect",
        on_threat: str = "block",  # block, warn, log
        scan_human_input: bool = True,
        scan_agent_output: bool = True,
        callback: Optional[Callable] = None,
    ):
        """
        Initialize AutoGen guard.
        
        Args:
            mode: Scan mode (protect, monitor, audit)
            on_threat: Action on threat detection
            scan_human_input: Scan human/user input
            scan_agent_output: Scan agent responses
            callback: Optional callback on threat
        """
        self._scanner = MemoryScanner(mode=mode)
        self._on_threat = on_threat
        self._scan_human = scan_human_input
        self._scan_agent = scan_agent_output
        self._callback = callback
        self._stats = AutoGenScanStats()
        self._threats: List[ConversationScanResult] = []
        self._secured_agents: set = set()
    
    def _scan_message(
        self,
        content: str,
        sender: str,
        receiver: str
    ) -> ConversationScanResult:
        """Scan message content."""
        self._stats.messages_scanned += 1
        
        result = self._scanner.scan(content)
        
        scan_result = ConversationScanResult(
            sender=sender,
            receiver=receiver,
            allowed=result.decision == Decision.ALLOW,
            decision=result.decision.value,
            risk_score=result.risk_score,
            threat_type=result.threat_type,
            content_preview=content[:100],
        )
        
        if not scan_result.allowed:
            self._threats.append(scan_result)
            self._stats.threats_blocked += 1
            
            logger.warning(
                f"Memgar: Threat from {sender} to {receiver} - "
                f"{scan_result.threat_type} (risk: {scan_result.risk_score})"
            )
            
            if self._callback:
                self._callback(scan_result)
            
            if self._on_threat == "block":
                raise MemgarAutoGenThreatError(
                    f"Message from {sender} blocked: {scan_result.threat_type}",
                    scan_result=scan_result
                )
        
        return scan_result
    
    def secure_agent(self, agent: Any) -> Any:
        """
        Secure a single AutoGen agent.
        
        Args:
            agent: AutoGen agent instance
            
        Returns:
            Secured agent
        """
        agent_name = getattr(agent, 'name', str(id(agent)))
        
        if agent_name in self._secured_agents:
            return agent
        
        # Wrap receive method
        if hasattr(agent, 'receive'):
            original_receive = agent.receive
            
            @functools.wraps(original_receive)
            def secured_receive(message, sender, *args, **kwargs):
                # Extract message content
                if isinstance(message, dict):
                    content = message.get('content', '')
                else:
                    content = str(message)
                
                # Determine if this is human input or agent output
                sender_name = getattr(sender, 'name', 'unknown')
                is_human = 'user' in sender_name.lower() or 'human' in sender_name.lower()
                
                should_scan = (is_human and self._scan_human) or (not is_human and self._scan_agent)
                
                if should_scan and content:
                    self._scan_message(content, sender_name, agent_name)
                
                return original_receive(message, sender, *args, **kwargs)
            
            agent.receive = secured_receive
        
        # Wrap send method
        if hasattr(agent, 'send'):
            original_send = agent.send
            
            @functools.wraps(original_send)
            def secured_send(message, recipient, *args, **kwargs):
                # Extract content
                if isinstance(message, dict):
                    content = message.get('content', '')
                else:
                    content = str(message)
                
                recipient_name = getattr(recipient, 'name', 'unknown')
                
                if content and self._scan_agent:
                    self._scan_message(content, agent_name, recipient_name)
                
                return original_send(message, recipient, *args, **kwargs)
            
            agent.send = secured_send
        
        self._secured_agents.add(agent_name)
        self._stats.agents_monitored += 1
        
        logger.info(f"Memgar: Secured agent '{agent_name}'")
        return agent
    
    def secure_agents(self, agents: List[Any]) -> List[Any]:
        """
        Secure multiple AutoGen agents.
        
        Args:
            agents: List of agents to secure
            
        Returns:
            List of secured agents
        """
        return [self.secure_agent(agent) for agent in agents]
    
    def secure_group_chat(self, group_chat: Any) -> Any:
        """
        Secure an AutoGen GroupChat.
        
        Args:
            group_chat: GroupChat instance
            
        Returns:
            Secured GroupChat
        """
        if hasattr(group_chat, 'agents'):
            self.secure_agents(group_chat.agents)
        
        self._stats.conversations += 1
        return group_chat
    
    def create_reply_hook(self) -> Callable:
        """
        Create a reply function hook for scanning.
        
        Returns:
            Hook function for register_reply
        """
        def hook(
            recipient: Any,
            messages: List[Dict],
            sender: Any,
            config: Any
        ) -> tuple:
            # Scan last message
            if messages:
                last_msg = messages[-1]
                content = last_msg.get('content', '')
                sender_name = last_msg.get('name', 'unknown')
                recipient_name = getattr(recipient, 'name', 'unknown')
                
                if content:
                    result = self._scan_message(content, sender_name, recipient_name)
                    if not result.allowed and self._on_threat == "block":
                        return True, "Message blocked by Memgar security."
            
            return False, None
        
        return hook
    
    @property
    def stats(self) -> AutoGenScanStats:
        """Get scanning statistics."""
        return self._stats
    
    @property
    def detected_threats(self) -> List[ConversationScanResult]:
        """Get all detected threats."""
        return self._threats.copy()
    
    def clear_threats(self) -> None:
        """Clear threat history."""
        self._threats.clear()


class MemgarAutoGenThreatError(Exception):
    """Exception raised when AutoGen threat is detected."""
    
    def __init__(self, message: str, scan_result: Optional[ConversationScanResult] = None):
        super().__init__(message)
        self.scan_result = scan_result


# Convenience functions
def secure_agent(agent: Any, **kwargs) -> Any:
    """
    Quick wrapper to secure an AutoGen agent.
    
    Args:
        agent: AutoGen agent instance
        **kwargs: Arguments for MemgarAutoGenGuard
        
    Returns:
        Secured agent
    """
    guard = MemgarAutoGenGuard(**kwargs)
    return guard.secure_agent(agent)


def secure_group_chat(group_chat: Any, **kwargs) -> Any:
    """
    Quick wrapper to secure an AutoGen GroupChat.
    
    Args:
        group_chat: GroupChat instance
        **kwargs: Arguments for MemgarAutoGenGuard
        
    Returns:
        Secured GroupChat
    """
    guard = MemgarAutoGenGuard(**kwargs)
    return guard.secure_group_chat(group_chat)
