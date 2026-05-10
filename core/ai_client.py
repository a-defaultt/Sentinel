import time
import logging
from typing import List, Dict, Any, Optional
from openai import OpenAI
import requests
from config import (
    NVIDIA_API_KEY, 
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
        self.client = OpenAI(
            base_url=NVIDIA_BASE_URL,
            api_key=NVIDIA_API_KEY
        )
        self.headers = {
            "Authorization": f"Bearer {NVIDIA_API_KEY}",
            "Accept": "application/json"
        }

    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        """Generates text using the primary model with a fallback mechanism."""
        try:
            logger.info(f"Generating text with primary model: {PRIMARY_MODEL}")
            response = self.client.chat.completions.create(
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
                response = self.client.chat.completions.create(
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

    def get_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generates embeddings for a list of texts."""
        try:
            logger.info(f"Generating embeddings for {len(texts)} chunks")
            # NVIDIA Embedding API might have specific requirements
            # Using OpenAI compatible endpoint
            response = self.client.embeddings.create(
                input=texts,
                model=EMBEDDING_MODEL,
                encoding_format="float"
            )
            return [item.embedding for item in response.data]
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
            raise

    def rerank(self, query: str, documents: List[str], top_n: int = 5) -> List[int]:
        """Reranks documents based on a query and returns the indices of the top results."""
        if not documents:
            return []
            
        url = f"{NVIDIA_BASE_URL}/reranking/nvidia/rerank-qa-mistral-4b" # Adjusted URL for reranker
        # Note: NVIDIA Rerank API might have a specific structure. 
        # Checking spec: rerank-qa-mistral-4b
        
        payload = {
            "model": RERANKER_MODEL,
            "query": {"text": query},
            "documents": [{"text": doc} for doc in documents],
            "top_n": top_n
        }

        try:
            logger.info(f"Reranking {len(documents)} documents for query")
            # Rerank API might not be OpenAI compatible, using requests
            response = requests.post(url, headers=self.headers, json=payload, timeout=NVIDIA_TIMEOUT)
            response.raise_for_status()
            results = response.json().get('results', [])
            
            # Return indices of top results
            return [item['index'] for item in results]
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
