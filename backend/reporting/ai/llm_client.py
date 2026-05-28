import os
import json
import urllib.request
import urllib.error
import logging
from typing import Dict, Optional, Callable

logger = logging.getLogger(__name__)

class LLMClient:
    """
    A lightweight, generic HTTP client for integrating with OpenAI, Google Gemini, 
    and local OpenAI-compatible endpoints (like LM Studio, vLLM, or Ollama).
    """
    def __init__(self, config: Dict[str, str] = None):
        self.config = config or {}

    def generate_json(self, system_prompt: str, user_prompt: str) -> Optional[Dict]:
        """
        Dispatches to the correct LLM provider based on environment variables.
        Expects a JSON response from the LLM.
        """
        provider = self.config.get("ai_provider", "openai").lower()
        api_key = self.config.get("ai_api_key", "")
        model = self.config.get("ai_model", "")

        if provider == "openai":
            api_key = api_key or os.environ.get("OPENAI_API_KEY")
            if not api_key:
                logger.warning("No OpenAI API key provided.")
                return None
            return self._call_openai(api_key, model or os.environ.get("OPENAI_MODEL", "gpt-4-turbo"), system_prompt, user_prompt)
            
        elif provider == "google":
            api_key = api_key or os.environ.get("GOOGLE_API_KEY")
            if not api_key:
                logger.warning("No Google API key provided.")
                return None
            return self._call_google(api_key, model or os.environ.get("GOOGLE_MODEL", "gemini-1.5-pro-latest"), system_prompt, user_prompt)
            
        elif provider == "local":
            # For local, the api_key field stores the endpoint URL
            endpoint = api_key or os.environ.get("LOCAL_LLM_ENDPOINT") 
            if not endpoint:
                logger.warning("No local endpoint provided.")
                return None
            return self._call_local(endpoint, model or os.environ.get("LOCAL_LLM_MODEL", "local-model"), system_prompt, user_prompt)
            
        logger.warning(f"Unknown AI provider configured: {provider}")
        return None

    def _call_openai(self, api_key: str, model: str, system_prompt: str, user_prompt: str) -> Optional[Dict]:
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }
        return self._make_request(url, headers, data, self._extract_openai)

    def _call_google(self, api_key: str, model: str, system_prompt: str, user_prompt: str) -> Optional[Dict]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        headers = {"Content-Type": "application/json"}
        
        data = {
            "system_instruction": {
                "parts": [{"text": system_prompt}]
            },
            "contents": [{
                "parts": [{"text": user_prompt}]
            }],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.2
            }
        }
        return self._make_request(url, headers, data, self._extract_google)

    def _call_local(self, endpoint: str, model: str, system_prompt: str, user_prompt: str) -> Optional[Dict]:
        headers = {"Content-Type": "application/json"}
        
        # Local models might require an API key, even if it's a placeholder
        local_api_key = os.environ.get("LOCAL_LLM_API_KEY")
        if local_api_key:
            headers["Authorization"] = f"Bearer {local_api_key}"
            
        data = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2
        }
        return self._make_request(endpoint, headers, data, self._extract_openai)

    def _make_request(self, url: str, headers: dict, data: dict, extract_fn: Callable) -> Optional[Dict]:
        req = urllib.request.Request(
            url, 
            data=json.dumps(data).encode("utf-8"), 
            headers=headers, 
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=45) as response:
                response_body = response.read().decode("utf-8")
                response_json = json.loads(response_body)
                content_str = extract_fn(response_json)
                
                # Try to parse the resulting text into JSON
                return json.loads(content_str)
                
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            logger.error(f"HTTPError from LLM API: {e.code} - {error_body}")
            return None
        except Exception as e:
            logger.error(f"Failed to generate from LLM API: {e}")
            return None

    def _extract_openai(self, response: dict) -> str:
        return response["choices"][0]["message"]["content"]

    def _extract_google(self, response: dict) -> str:
        return response["candidates"][0]["content"]["parts"][0]["text"]
