"""
Memory Module for Project Sentinel.
Manages persistent vector storage using ChromaDB for RAG-based threat analysis.
"""
import chromadb
from chromadb.api.types import EmbeddingFunction, Documents, Embeddings
import pandas as pd
import json
import logging
from typing import List, Dict, Any, Optional
import tiktoken
from config import CHROMA_DATA_PATH, EMBEDDING_MODEL, logger
from core.ai_client import NVIDIAClient

class NVIDIAEmbeddingFunction(EmbeddingFunction):
    def __init__(self, ai_client: NVIDIAClient):
        self.ai_client = ai_client

    def __call__(self, input: Documents) -> Embeddings:
        # Default to passage for general embedding tasks in ChromaDB
        # We'll use passage here, but queries might need 'query'
        return self.ai_client.get_embeddings(input, input_type="passage")

class SentinelMemory:
    def __init__(self, ai_client: NVIDIAClient):
        self.client = chromadb.PersistentClient(path=str(CHROMA_DATA_PATH))
        self.ai_client = ai_client
        self.embedding_function = NVIDIAEmbeddingFunction(ai_client)
        self.collection = self.client.get_or_create_collection(
            name="sentinel_alerts",
            embedding_function=self.embedding_function
        )
        self.tokenizer = tiktoken.get_encoding("cl100k_base")

    def _truncate_text(self, text: str, max_tokens: int = 512) -> str:
        """Truncates text to a maximum number of tokens."""
        tokens = self.tokenizer.encode(text)
        if len(tokens) <= max_tokens:
            return text
        return self.tokenizer.decode(tokens[:max_tokens])

    def _flatten_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Flattens metadata values into strings as ChromaDB doesn't support lists/dicts in metadata."""
        flattened = {}
        for key, value in metadata.items():
            if isinstance(value, (list, dict)):
                flattened[key] = str(value) if not isinstance(value, list) else ",".join(map(str, value))
            elif value is None:
                flattened[key] = ""
            else:
                flattened[key] = value
        return flattened

    def store_alerts(self, df: pd.DataFrame):
        """Stores aggregated alerts in ChromaDB using upsert to avoid duplicates."""
        if df.empty:
            return

        documents = []
        metadatas = []
        ids = []

        for _, row in df.iterrows():
            alert_dict = row.to_dict()
            clean_metadata = {k: v for k, v in alert_dict.items() if not k.startswith('enrichment_')}
            
            if 'enrichment_ip' in alert_dict and isinstance(alert_dict['enrichment_ip'], dict):
                for k, v in alert_dict['enrichment_ip'].items():
                    clean_metadata[f"ip_{k}"] = v
            
            if 'enrichment_hash' in alert_dict and isinstance(alert_dict['enrichment_hash'], dict):
                for k, v in alert_dict['enrichment_hash'].items():
                    clean_metadata[f"hash_{k}"] = v

            # Construct more detailed document string for better RAG
            doc_str = f"Alert {row.get('rule_id')} - {row.get('description')}. "
            doc_str += f"Groups: {row.get('rule_groups')}. "
            doc_str += f"Source IP: {row.get('srcip')}. Agent: {row.get('agent_name')} ({row.get('agent_id')}). "
            doc_str += f"Location: {row.get('location')}. "
            if row.get('mitre_ids'):
                doc_str += f"MITRE: {row.get('mitre_ids')}. "
            if row.get('cve'):
                doc_str += f"CVE: {row.get('cve')}. "
            
            doc_str = self._truncate_text(doc_str)
            
            documents.append(doc_str)
            metadatas.append(self._flatten_metadata(clean_metadata))
            
            # Robust unique ID: date + rule_id + srcip + agent_id
            unique_id = f"{row.get('timestamp')[:10]}_{row.get('rule_id')}_{row.get('srcip')}_{row.get('agent_id')}"
            ids.append(unique_id)

        if documents:
            logger.info(f"Upserting {len(documents)} alerts in ChromaDB")
            self.collection.upsert(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )

    def query_similar_threats(self, query_texts: List[str], n_results: int = 20) -> List[str]:
        """Queries ChromaDB for similar threats and reranks the results."""
        if not query_texts:
            return []

        # Manually embed queries with input_type="query" for NVIDIA models
        query_embeddings = self.ai_client.get_embeddings(query_texts, input_type="query")

        all_results = []
        for i, query_emb in enumerate(query_embeddings):
            results = self.collection.query(
                query_embeddings=[query_emb],
                n_results=n_results
            )
            if results['documents']:
                all_results.extend(results['documents'][0])

        # De-duplicate results
        unique_results = list(set(all_results))
        
        if not unique_results:
            return []

        # Rerank
        # Use the first query as the rerank context
        primary_query = query_texts[0]
        top_indices = self.ai_client.rerank(primary_query, unique_results, top_n=5)
        
        return [unique_results[i] for i in top_indices]

if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    try:
        ai = NVIDIAClient()
        memory = SentinelMemory(ai)
        # memory.store_alerts(pd.DataFrame(...))
    except Exception as e:
        print(f"Memory init failed: {e}")
