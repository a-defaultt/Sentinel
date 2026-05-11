"""
AI Client Module for Project Sentinel.
Provides a unified interface for the NVIDIA Build API, including generation, embedding, and reranking.
"""
import time
import logging
from typing import List, Dict, Any, Optional
from openai import OpenAI
import requests
from config import (
    NVIDIA_PRIMARY_KEY,
    NVIDIA_FALLBACK_KEY,
    NVIDIA_EMBEDDING_KEY,
    NVIDIA_RERANKING_KEY,
    NVIDIA_BASE_URL, 
    PRIMARY_MODEL, 
    FALLBACK_MODEL, 
    EMBEDDING_MODEL, 
    RERANKER_MODEL,
    NVIDIA_TIMEOUT,
    NVIDIA_FALLBACK_TIMEOUT,
    logger
)

class NVIDIAClient:
    def __init__(self):
        # We'll initialize clients as needed since they have different keys
        self.base_url = NVIDIA_BASE_URL

    def _get_client(self, api_key: str):
        return OpenAI(base_url=self.base_url, api_key=api_key)

    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        """Generates text using the primary model with a fallback mechanism."""
        try:
            logger.info(f"Generating text with primary model: {PRIMARY_MODEL}")
            client = self._get_client(NVIDIA_PRIMARY_KEY)
            response = client.chat.completions.create(
                model=PRIMARY_MODEL,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
                max_tokens=4096,
                timeout=NVIDIA_TIMEOUT
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.warning(f"Primary model ({PRIMARY_MODEL}) failed: {e}. Attempting fallback...")
            try:
                client = self._get_client(NVIDIA_FALLBACK_KEY)
                response = client.chat.completions.create(
                    model=FALLBACK_MODEL,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    temperature=0.2,
                    max_tokens=4096,
                    timeout=NVIDIA_FALLBACK_TIMEOUT
                )
                return response.choices[0].message.content
            except Exception as fe:
                logger.error(f"Fallback model ({FALLBACK_MODEL}) also failed: {fe}")
                raise

    def get_embeddings(self, texts: List[str], input_type: str = "passage") -> List[List[float]]:
        """Generates embeddings for a list of texts using requests to include input_type."""
        try:
            logger.info(f"Generating embeddings for {len(texts)} chunks with input_type={input_type}")
            url = f"{self.base_url}/embeddings"
            headers = {
                "Authorization": f"Bearer {NVIDIA_EMBEDDING_KEY}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            payload = {
                "model": EMBEDDING_MODEL,
                "input": texts,
                "input_type": input_type,
                "encoding_format": "float"
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=NVIDIA_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            return [item['embedding'] for item in data['data']]
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
            raise

    def rerank(self, query: str, documents: List[str], top_n: int = 5) -> List[int]:
        """Reranks documents based on a query and returns the indices of the top results."""
        if not documents:
            return []
            
        # Updated NVIDIA Rerank endpoint and structure
        url = f"{self.base_url}/retrieval/nvidia/reranking"
        
        headers = {
            "Authorization": f"Bearer {NVIDIA_RERANKING_KEY}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        payload = {
            "model": RERANKER_MODEL,
            "query": {"text": query},
            "passages": [{"text": doc} for doc in documents],
            "truncate": "END"
        }

        try:
            logger.info(f"Reranking {len(documents)} documents for query")
            response = requests.post(url, headers=headers, json=payload, timeout=NVIDIA_TIMEOUT)
            response.raise_for_status()
            results = response.json().get('rankings', []) # NVIDIA typically returns 'rankings'
            
            # Extract top indices
            # Format: [{"index": 0, "logit": ...}, ...]
            top_results = sorted(results, key=lambda x: x.get('logit', 0), reverse=True)[:top_n]
            return [item['index'] for item in top_results]
        except Exception as e:
            logger.error(f"Reranking failed: {e}. Returning first {top_n} results as fallback.")
            return list(range(min(len(documents), top_n)))

if __name__ == "__main__":
    # Test (requires API key)
    logging.basicConfig(level=logging.INFO)
    try:
        client = NVIDIAClient()
        # print(client.generate_text("You are a helpful assistant.", "Hello!"))
    except Exception as e:
        print(f"Setup failed: {e}")
