"""Multi-company federation layer for the Memgar simulation.

The single-org runner (``simulation/runner.py``) pits one five-agent
company against 29 in-house attacks. Real deployments are not islands:
companies federate. They share a vendor portal, consume the same MCP
tool servers, integrate B2B agent buses, and extend *partial* trust to
partner organisations. That federation is the modern attack surface —
supply-chain agent compromise, cross-tenant RAG bleed, A2A identity
spoofing, tool-result injection — none of which a single-org model can
express.

This module builds a `Federation` of N independent companies. Each
company is a full org (the same agents the single-org runner uses) with
its **own** message bus, so agent names never collide. Cross-company
delivery is explicit: an attacker posts into the *target* company's bus
exactly the way a real attacker emails into your domain or pushes a
document to a shared portal.

Two federation-wide resources are deliberately *shared* between tenants:

  * a vendor-portal RAG index, and
  * an MCP / tool provider,

so a single poisoning event can be observed reaching every tenant. That
is the multi-tenant blast-radius the cross-company scenarios exercise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from memgar.agents import TrustLevel

from .world import World, Message
from .runner import build_world, SimContext, _seed_legitimate_rag
from .infrastructure.rag import (
    NaiveRagIndex, ShieldedRagIndex, Document,
)
from .infrastructure.tools import NaiveToolRuntime, ShieldedToolRuntime


@dataclass
class Company:
    """One organisation in the federation."""
    cid: str
    world: World
    ctx: SimContext
    mode: str
    # Trust the *home* company extends to this one over the B2B bus.
    # PARTNER companies start MEDIUM; the rogue supply-chain company is
    # (mis)registered HIGH precisely to model an over-trusted vendor.
    b2b_trust: TrustLevel = TrustLevel.MEDIUM


class Federation:
    """A set of companies plus the shared multi-tenant resources.

    The home company (``home_id``) is the defender we score. Partner
    companies are either honest integrators or attacker-controlled,
    depending on the scenario.
    """

    def __init__(self, mode: str, scenario_id: str, company_ids: List[str],
                 *, home_id: Optional[str] = None,
                 shared_rag: bool = True, shared_tools: bool = True) -> None:
        self.mode = mode
        self.scenario_id = scenario_id
        self.company_ids = company_ids
        self.home_id = home_id or company_ids[0]

        # Multi-tenant shared resources: built ONCE, handed to every
        # company. Poison the portal once → every tenant's researcher is
        # exposed. This is the federation blast radius.
        self.shared_rag: Any = None
        self.shared_tools: Any = None
        if shared_rag:
            self.shared_rag = (ShieldedRagIndex() if mode == "shielded"
                               else NaiveRagIndex())
            _seed_legitimate_rag(self.shared_rag)
        if shared_tools:
            self.shared_tools = (ShieldedToolRuntime() if mode == "shielded"
                                 else NaiveToolRuntime())

        self.companies: Dict[str, Company] = {}
        for cid in company_ids:
            world, ctx = build_world(
                mode, scenario_id,
                shared_rag=self.shared_rag, shared_tools=self.shared_tools,
                company=cid,
            )
            self.companies[cid] = Company(cid=cid, world=world, ctx=ctx, mode=mode)

        # Wire the cross-company trust graph: every partner is registered
        # with the home company's coordinator at its b2b_trust level. In
        # shielded mode this is what AgentSecurityGuard consults when a
        # partner agent tries to relay across the boundary.
        self._wire_b2b_trust()

    # -- federation helpers ---------------------------------------------

    def home(self) -> Company:
        return self.companies[self.home_id]

    def _wire_b2b_trust(self) -> None:
        home = self.companies[self.home_id]
        sec = home.ctx.coordinator.security
        if sec is None:
            return
        for cid, comp in self.companies.items():
            if cid == self.home_id:
                continue
            partner_principal = f"{cid}.coordinator"
            sec.set_trust(home.ctx.coordinator.name, partner_principal, comp.b2b_trust)
            sec.set_trust(partner_principal, home.ctx.coordinator.name, comp.b2b_trust)

    def set_partner_trust(self, cid: str, level: TrustLevel) -> None:
        """Mark a partner company's trust. Used to model an over-trusted
        (HIGH) compromised vendor vs a normal MEDIUM integrator."""
        self.companies[cid].b2b_trust = level
        self._wire_b2b_trust()

    def b2b_relay(self, src_company: str, dst_company: str, body: str,
                  *, dst_agent: str = "finance", kind: str = "memory_write",
                  claimed_principal: Optional[str] = None) -> bool:
        """Deliver a message from one company to another across the B2B
        boundary.

        Shielded mode applies two layers at the boundary itself:

          1. **Partner authentication / trust gate.** The destination only
             accepts cross-company traffic from a partner it has registered
             at MEDIUM or higher. An unregistered or NONE/LOW-trust
             principal — i.e. an A2A agent-card spoofer claiming to be a
             partner — is dropped here.
          2. **Content scan** via AgentSecurityGuard for the principals
             that do clear the trust gate.

        Authenticated-but-poisoned content from an over-trusted partner
        still passes the boundary; it is the destination agent's shielded
        memory store and tool runtime that must catch it downstream — which
        is exactly the layered story we want to demonstrate.

        ``claimed_principal`` models identity spoofing: the wire says it is
        from ``vendorco.coordinator`` but the sending company is the
        attacker. Trust is resolved against the *sending* company, never the
        claimed string."""
        dst = self.companies[dst_company]
        src = self.companies.get(src_company)
        principal = claimed_principal or f"{src_company}.coordinator"
        coord = dst.ctx.coordinator

        if dst.mode == "shielded":
            # Trust resolves against the real sender, not the claimed name.
            src_trust = src.b2b_trust if src is not None else TrustLevel.NONE
            if src_trust.value < TrustLevel.MEDIUM.value:
                coord.blocked_messages.append({
                    "tick": dst.world.tick, "source": principal,
                    "real_company": src_company, "target": dst_agent,
                    "reason": "untrusted-or-spoofed-partner",
                    "trust": src_trust.name, "preview": body[:120],
                    "cross_company": True,
                })
                return False
            if coord.security is not None:
                assess = coord.security.validate_message(
                    source=principal, target=dst_agent, message=body)
                if not assess.is_safe and assess.action.value == "block":
                    coord.blocked_messages.append({
                        "tick": dst.world.tick, "source": principal,
                        "target": dst_agent, "risk": assess.overall_risk,
                        "preview": body[:120], "cross_company": True,
                    })
                    return False

        dst.world.post(Message(
            msg_id=dst.world.new_id("b2b"),
            sender=principal, recipient=dst_agent,
            channel="agent_bus", kind=kind, body=body,
            tick=dst.world.tick,
            metadata={"cross_company": True, "src_company": src_company},
        ))
        return True

    def drive_all(self, ticks: int) -> None:
        """Advance every company's clock and agents in lockstep."""
        for _ in range(ticks):
            for comp in self.companies.values():
                comp.ctx.drive(comp.world, ticks=1)

    def email_into(self, cid: str, sender: str, body: str, *,
                   recipient: str = "triage", from_domain: str = "external.example",
                   dkim: bool = False, kind: str = "memory_write") -> None:
        """Drop an inbound email into a specific company's perimeter."""
        comp = self.companies[cid]
        comp.world.post(Message(
            msg_id=comp.world.new_id("email"),
            sender=sender, recipient=recipient, channel="email",
            kind=kind, body=body, tick=comp.world.tick,
            metadata={"from_domain": from_domain, "dkim_verified": dkim},
        ))

    def add_shared_doc(self, doc: Document) -> Any:
        """Upload a document to the shared vendor-portal RAG (all tenants)."""
        if self.shared_rag is None:
            return None
        return self.shared_rag.add(doc) if hasattr(self.shared_rag, "add") else None
