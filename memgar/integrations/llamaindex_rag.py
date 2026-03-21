"""
Memgar LlamaIndex RAG Integration
=================================

Trust-aware retrieval integration for LlamaIndex.

Provides:
- MemgarRetriever: Trust-aware retriever for LlamaIndex
- MemgarNodePostprocessor: Trust-based node filtering
- Query engine helpers

Example:
    from llama_index.core import VectorStoreIndex
    from memgar.integrations.llamaindex_rag import MemgarRetriever
    
    # Create index
    index = VectorStoreIndex.from_documents(documents)
    
    # Wrap with Memgar
    retriever = MemgarRetriever(
        base_retriever=index.as_retriever(),
        min_trust_score=0.3,
    )
    
    # Use in query engine
    query_engine = index.as_query_engine(retriever=retriever)
"""

import logging
from typing import List, Dict, Optional, Any, Callable
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Import base classes (handle if LlamaIndex not installed)
try:
    from llama_index.core.retrievers import BaseRetriever
    from llama_index.core.schema import NodeWithScore, QueryBundle, TextNode
    from llama_index.core.postprocessor import BaseNodePostprocessor
    from llama_index.core.callbacks import CallbackManager
    LLAMAINDEX_AVAILABLE = True
except ImportError:
    LLAMAINDEX_AVAILABLE = False
    BaseRetriever = object
    BaseNodePostprocessor = object
    NodeWithScore = Any
    QueryBundle = Any
    TextNode = Any
    CallbackManager = Any

from ..retriever import (
    TrustAwareRetriever,
    RetrievalMetadata,
    RetrievalResult,
    RetrievedDocument,
    DecayFunction,
)


class MemgarRetriever(BaseRetriever if LLAMAINDEX_AVAILABLE else object):
    """
    Trust-aware LlamaIndex retriever.
    
    Drop-in replacement that adds trust-weighted ranking,
    temporal decay, and anomaly detection.
    
    Example:
        from llama_index.core import VectorStoreIndex
        
        # Create index
        index = VectorStoreIndex.from_documents(docs)
        base_retriever = index.as_retriever(similarity_top_k=10)
        
        # Wrap with Memgar
        secure_retriever = MemgarRetriever(
            base_retriever=base_retriever,
            min_trust_score=0.3,
        )
        
        # Use in query engine
        query_engine = index.as_query_engine(retriever=secure_retriever)
    """
    
    def __init__(
        self,
        base_retriever: Any,
        min_trust_score: float = 0.3,
        trust_weight_factor: float = 0.3,
        enable_temporal_decay: bool = True,
        decay_half_life_days: float = 30.0,
        enable_anomaly_detection: bool = True,
        filter_flagged: bool = True,
        filter_high_risk: bool = True,
        high_risk_threshold: int = 70,
        similarity_top_k: int = 5,
        return_metadata: bool = False,
        metadata_store: Optional[Dict[str, RetrievalMetadata]] = None,
        on_anomaly: Optional[Callable] = None,
        callback_manager: Optional[CallbackManager] = None,
    ):
        """
        Initialize Memgar retriever for LlamaIndex.
        
        Args:
            base_retriever: LlamaIndex retriever to wrap
            min_trust_score: Minimum trust score (0-1)
            trust_weight_factor: How much trust affects ranking
            enable_temporal_decay: Enable time-based decay
            decay_half_life_days: Half-life for decay
            enable_anomaly_detection: Detect suspicious patterns
            filter_flagged: Filter flagged documents
            filter_high_risk: Filter high-risk documents
            high_risk_threshold: Risk score threshold
            similarity_top_k: Number of documents to return
            return_metadata: Include Memgar metadata in node
            metadata_store: Pre-populated metadata store
            on_anomaly: Callback for anomaly detection
            callback_manager: LlamaIndex callback manager
        """
        if LLAMAINDEX_AVAILABLE:
            super().__init__(callback_manager=callback_manager)
        
        self.base_retriever = base_retriever
        self.return_metadata = return_metadata
        self.on_anomaly = on_anomaly
        self.similarity_top_k = similarity_top_k
        
        # Create trust-aware retriever
        self.trust_retriever = TrustAwareRetriever(
            retrieve_fn=self._base_retrieve,
            min_trust_score=min_trust_score,
            trust_weight_factor=trust_weight_factor,
            enable_temporal_decay=enable_temporal_decay,
            decay_half_life_days=decay_half_life_days,
            enable_anomaly_detection=enable_anomaly_detection,
            filter_flagged=filter_flagged,
            filter_high_risk=filter_high_risk,
            high_risk_threshold=high_risk_threshold,
            top_k=similarity_top_k,
        )
        
        # Load metadata if provided
        if metadata_store:
            for doc_id, metadata in metadata_store.items():
                self.trust_retriever.set_metadata(doc_id, metadata)
    
    def _base_retrieve(
        self,
        query: str,
        k: int = 10,
        **kwargs
    ) -> List[Dict]:
        """Call base retriever and convert to dict format."""
        query_bundle = QueryBundle(query_str=query) if LLAMAINDEX_AVAILABLE else query
        
        # Get nodes from base retriever
        if hasattr(self.base_retriever, 'retrieve'):
            nodes = self.base_retriever.retrieve(query_bundle)
        elif hasattr(self.base_retriever, '_retrieve'):
            nodes = self.base_retriever._retrieve(query_bundle)
        else:
            nodes = []
        
        # Convert to dict format for TrustAwareRetriever
        results = []
        for node_with_score in nodes[:k]:
            if hasattr(node_with_score, 'node'):
                node = node_with_score.node
                score = node_with_score.score or 0.5
            else:
                node = node_with_score
                score = 0.5
            
            # Extract node info
            content = node.get_content() if hasattr(node, 'get_content') else str(node)
            node_id = node.node_id if hasattr(node, 'node_id') else str(hash(content))
            
            results.append({
                "content": content,
                "doc_id": node_id,
                "score": score,
                "metadata": node.metadata if hasattr(node, 'metadata') else {},
                "_node": node,  # Keep original node
            })
        
        return results
    
    def _retrieve(self, query_bundle: QueryBundle) -> List[NodeWithScore]:
        """
        Retrieve nodes with trust-aware ranking.
        
        This is the main retrieval method called by LlamaIndex.
        """
        query = query_bundle.query_str if hasattr(query_bundle, 'query_str') else str(query_bundle)
        
        # Get trust-aware results
        result = self.trust_retriever.retrieve(query, top_k=self.similarity_top_k)
        
        # Handle anomalies
        if result.anomalies_detected > 0 and self.on_anomaly:
            self.on_anomaly(result.anomaly_details)
        
        # Convert back to LlamaIndex NodeWithScore
        nodes_with_scores = []
        
        for doc in result.documents:
            # Get original node if available
            if doc.metadata and doc.metadata.custom_data and "_node" in doc.metadata.custom_data:
                node = doc.metadata.custom_data["_node"]
            else:
                # Create new TextNode
                node = TextNode(
                    text=doc.content,
                    id_=doc.doc_id,
                    metadata={
                        "trust_score": doc.trust_weight,
                        "is_trusted": doc.is_trusted,
                        "final_score": doc.final_score,
                    }
                )
            
            # Add Memgar metadata if requested
            if self.return_metadata and hasattr(node, 'metadata'):
                node.metadata["memgar"] = {
                    "similarity_score": doc.similarity_score,
                    "trust_adjusted_score": doc.trust_adjusted_score,
                    "final_score": doc.final_score,
                    "trust_weight": doc.trust_weight,
                    "temporal_decay": doc.temporal_decay,
                    "is_trusted": doc.is_trusted,
                    "is_anomalous": doc.is_anomalous,
                }
            
            nodes_with_scores.append(NodeWithScore(
                node=node,
                score=doc.final_score,
            ))
        
        return nodes_with_scores
    
    def retrieve(self, str_or_query_bundle: Any) -> List[NodeWithScore]:
        """Public retrieve method."""
        if isinstance(str_or_query_bundle, str):
            query_bundle = QueryBundle(query_str=str_or_query_bundle)
        else:
            query_bundle = str_or_query_bundle
        return self._retrieve(query_bundle)
    
    def set_node_metadata(
        self,
        node_id: str,
        trust_score: float = 0.5,
        source_type: str = "unknown",
        created_at: Optional[datetime] = None,
        risk_score: int = 0,
        flagged: bool = False,
        **extra
    ) -> None:
        """Set metadata for a node."""
        import hashlib
        metadata = RetrievalMetadata(
            doc_id=node_id,
            content_hash=hashlib.sha256(node_id.encode()).hexdigest(),
            trust_score=trust_score,
            source_type=source_type,
            created_at=created_at or datetime.now(timezone.utc),
            risk_score=risk_score,
            flagged=flagged,
            custom_data=extra,
        )
        self.trust_retriever.set_metadata(node_id, metadata)
    
    def get_statistics(self) -> Dict:
        """Get retrieval statistics."""
        return self.trust_retriever.get_statistics()


class MemgarNodePostprocessor(BaseNodePostprocessor if LLAMAINDEX_AVAILABLE else object):
    """
    Trust-based node postprocessor for LlamaIndex.
    
    Use when you want to keep your existing retriever but add
    trust-based filtering as a postprocessing step.
    
    Example:
        from llama_index.core import VectorStoreIndex
        
        index = VectorStoreIndex.from_documents(docs)
        
        # Add postprocessor
        postprocessor = MemgarNodePostprocessor(
            min_trust_score=0.3,
            filter_anomalous=True,
        )
        
        query_engine = index.as_query_engine(
            node_postprocessors=[postprocessor]
        )
    """
    
    def __init__(
        self,
        min_trust_score: float = 0.3,
        filter_anomalous: bool = True,
        filter_flagged: bool = True,
        metadata_key: str = "trust_score",
        enable_reranking: bool = True,
        trust_weight: float = 0.3,
    ):
        """
        Initialize postprocessor.
        
        Args:
            min_trust_score: Minimum trust score to keep
            filter_anomalous: Filter anomalous nodes
            filter_flagged: Filter flagged nodes
            metadata_key: Key for trust score in node metadata
            enable_reranking: Rerank based on trust
            trust_weight: Weight for trust in reranking
        """
        if LLAMAINDEX_AVAILABLE:
            super().__init__()
        
        self.min_trust_score = min_trust_score
        self.filter_anomalous = filter_anomalous
        self.filter_flagged = filter_flagged
        self.metadata_key = metadata_key
        self.enable_reranking = enable_reranking
        self.trust_weight = trust_weight
    
    def _postprocess_nodes(
        self,
        nodes: List[NodeWithScore],
        query_bundle: Optional[QueryBundle] = None,
    ) -> List[NodeWithScore]:
        """Postprocess nodes with trust filtering."""
        filtered_nodes = []
        
        for node_with_score in nodes:
            node = node_with_score.node
            score = node_with_score.score or 0.5
            
            # Get trust score from metadata
            metadata = node.metadata if hasattr(node, 'metadata') else {}
            trust_score = metadata.get(self.metadata_key, 0.5)
            
            # Filter by trust
            if trust_score < self.min_trust_score:
                continue
            
            # Filter flagged
            if self.filter_flagged and metadata.get("flagged", False):
                continue
            
            # Filter anomalous
            if self.filter_anomalous and metadata.get("is_anomalous", False):
                continue
            
            # Calculate adjusted score
            if self.enable_reranking:
                adjusted_score = score * (
                    1 - self.trust_weight + 
                    self.trust_weight * trust_score
                )
            else:
                adjusted_score = score
            
            # Create new node with adjusted score
            filtered_nodes.append(NodeWithScore(
                node=node,
                score=adjusted_score,
            ))
        
        # Sort by adjusted score
        if self.enable_reranking:
            filtered_nodes.sort(key=lambda x: x.score or 0, reverse=True)
        
        return filtered_nodes
    
    # Alias for compatibility
    def postprocess_nodes(
        self,
        nodes: List[NodeWithScore],
        query_bundle: Optional[QueryBundle] = None,
    ) -> List[NodeWithScore]:
        """Public postprocess method."""
        return self._postprocess_nodes(nodes, query_bundle)


# =============================================================================
# QUERY ENGINE HELPERS
# =============================================================================

def create_secure_query_engine(
    index: Any,
    min_trust_score: float = 0.3,
    similarity_top_k: int = 5,
    response_mode: str = "compact",
    on_anomaly: Optional[Callable] = None,
) -> Any:
    """
    Create a trust-aware query engine.
    
    Example:
        from llama_index.core import VectorStoreIndex
        
        index = VectorStoreIndex.from_documents(docs)
        engine = create_secure_query_engine(
            index=index,
            min_trust_score=0.4,
        )
        
        response = engine.query("What is our policy?")
    """
    # Create Memgar retriever
    base_retriever = index.as_retriever(similarity_top_k=similarity_top_k * 2)
    secure_retriever = MemgarRetriever(
        base_retriever=base_retriever,
        min_trust_score=min_trust_score,
        similarity_top_k=similarity_top_k,
        on_anomaly=on_anomaly,
    )
    
    # Create query engine with secure retriever
    query_engine = index.as_query_engine(
        retriever=secure_retriever,
        response_mode=response_mode,
    )
    
    return query_engine


def create_secure_chat_engine(
    index: Any,
    min_trust_score: float = 0.3,
    similarity_top_k: int = 5,
    chat_mode: str = "condense_plus_context",
    on_anomaly: Optional[Callable] = None,
) -> Any:
    """
    Create a trust-aware chat engine.
    
    Example:
        engine = create_secure_chat_engine(
            index=index,
            min_trust_score=0.4,
        )
        
        response = engine.chat("Hello!")
    """
    # Create Memgar retriever
    base_retriever = index.as_retriever(similarity_top_k=similarity_top_k * 2)
    secure_retriever = MemgarRetriever(
        base_retriever=base_retriever,
        min_trust_score=min_trust_score,
        similarity_top_k=similarity_top_k,
        on_anomaly=on_anomaly,
    )
    
    # Create chat engine
    chat_engine = index.as_chat_engine(
        retriever=secure_retriever,
        chat_mode=chat_mode,
    )
    
    return chat_engine


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def check_llamaindex_available() -> bool:
    """Check if LlamaIndex is available."""
    return LLAMAINDEX_AVAILABLE


def extract_trust_from_metadata(
    nodes: List[Any],
    trust_key: str = "trust_score",
    default_trust: float = 0.5,
) -> Dict[str, float]:
    """Extract trust scores from node metadata."""
    trust_map = {}
    
    for node in nodes:
        if hasattr(node, 'node'):
            actual_node = node.node
        else:
            actual_node = node
        
        node_id = actual_node.node_id if hasattr(actual_node, 'node_id') else str(hash(str(actual_node)))
        metadata = actual_node.metadata if hasattr(actual_node, 'metadata') else {}
        
        trust_map[node_id] = metadata.get(trust_key, default_trust)
    
    return trust_map
