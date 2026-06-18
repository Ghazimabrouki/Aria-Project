import asyncio
import os
import random

import httpx

from response.ai_engine.main import logger, settings, AI_TIMEOUT_FALLBACK
import response.ai_engine.main as _main_module


async def _get_timeout(prompt_length: int) -> int:
    """Get adaptive timeout with fallback."""
    try:
        from response.adaptive import get_timeout_safe
        return await get_timeout_safe(prompt_length, settings.llm_model)
    except Exception:
        # Google Gemini is much faster (~3-5s vs 40-120s for Ollama)
        if settings.llm_provider == "google":
            return 30
        return AI_TIMEOUT_FALLBACK


def _setup_ollama_model():
    """Initialize LLM model from settings."""
    if settings.llm_model:
        _main_module._ollama_model = settings.llm_model


async def _call_ollama_with_retry(prompt: str, max_retries: int = 2) -> str:
    """
    Send prompt to Ollama with fast retry.
    Returns the raw response text.
    """
    last_error = None
    for attempt in range(max_retries):
        try:
            # Get adaptive timeout for this specific prompt
            timeout_value = await _get_timeout(len(prompt))

            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=5.0, read=timeout_value, write=5.0, pool=5.0)
            ) as client:
                resp = await client.post(
                    f"{settings.ollama_host}/api/generate",
                    json={"model": settings.llm_model, "prompt": prompt, "stream": False},
                )
                resp.raise_for_status()
                result = resp.json().get("response", "")
                logger.info("ollama_request_success", attempt=attempt + 1, response_len=len(result))
                return result
        except Exception as e:
            last_error = e
            wait_time = (2 ** attempt) + random.uniform(0, 0.5)  # Faster backoff
            logger.warning("ollama_request_retry", attempt=attempt + 1, wait=wait_time, error=str(e))
            if attempt < max_retries - 1:
                await asyncio.sleep(wait_time)

    logger.error("ollama_request_failed_all_retries", attempts=max_retries, error=str(last_error))
    raise last_error


async def _call_google(prompt: str) -> str:
    """Send prompt to Google Gemini and return the raw response text."""
    api_key = os.environ.get("GOOGLE_API_KEY") or getattr(settings, "google_api_key", None)
    if not api_key:
        raise ValueError("GOOGLE_API_KEY not configured")

    model = settings.llm_model or "gemini-2.0-flash"

    logger.info("google_gemini_request_start", model=model, prompt_len=len(prompt))

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 2048,
        }
    }

    last_error = None
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0)) as client:
                resp = await client.post(url, json=payload)

                # Handle rate limiting with retry
                if resp.status_code == 429:
                    wait_time = (2 ** attempt) * 2  # 2, 4, 8 seconds
                    logger.warning("google_rate_limited", attempt=attempt + 1, wait=wait_time)
                    if attempt < 2:
                        await asyncio.sleep(wait_time)
                        continue
                    raise Exception("Rate limited - too many requests")

                resp.raise_for_status()
                result = resp.json()

                if "candidates" in result and len(result["candidates"]) > 0:
                    content = result["candidates"][0].get("content", {})
                    parts = content.get("parts", [])
                    if parts:
                        text = parts[0].get("text", "")
                        logger.info("google_gemini_request_success", response_len=len(text))
                        return text

                raise ValueError(f"Gemini response missing content: {result}")

        except httpx.HTTPStatusError as e:
            last_error = e
            if e.response.status_code == 429:
                wait_time = (2 ** attempt) * 2
                logger.warning("google_http_rate_limited", attempt=attempt + 1, wait=wait_time)
                if attempt < 2:
                    await asyncio.sleep(wait_time)
                    continue
        except Exception as e:
            last_error = e
            logger.warning("google_gemini_request_error", attempt=attempt + 1, error=str(e))
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)
                continue

    raise last_error


async def _call_openrouter(prompt: str) -> str:
    """Send prompt to OpenRouter API (DeepSeek, Qwen, etc.)."""
    api_key = getattr(settings, "openrouter_api_key", None)
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY not configured")

    model = settings.llm_model or "deepseek/deepseek-chat"

    logger.info("openrouter_request_start", model=model, prompt_len=len(prompt))

    url = "https://openrouter.ai/api/v1/chat/completions"

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 2048,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "OpenSOAR",
    }

    last_error = None
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(connect=15.0, read=120.0, write=15.0, pool=15.0)) as client:
                resp = await client.post(url, json=payload, headers=headers)

                if resp.status_code == 429:
                    wait_time = (2 ** attempt) * 3  # 3, 6, 12 seconds
                    logger.warning("openrouter_rate_limited", attempt=attempt + 1, wait=wait_time)
                    if attempt < 2:
                        await asyncio.sleep(wait_time)
                        continue
                    raise Exception("Rate limited - too many requests")

                resp.raise_for_status()
                result = resp.json()

                if "choices" in result and len(result["choices"]) > 0:
                    text = result["choices"][0].get("message", {}).get("content", "")
                    logger.info("openrouter_request_success", response_len=len(text))
                    return text

                raise ValueError(f"OpenRouter response missing content: {result}")

        except httpx.HTTPStatusError as e:
            last_error = e
            if e.response.status_code == 429:
                wait_time = (2 ** attempt) * 3
                logger.warning("openrouter_http_rate_limited", attempt=attempt + 1, wait=wait_time)
                if attempt < 2:
                    await asyncio.sleep(wait_time)
                    continue
        except Exception as e:
            last_error = e
            logger.warning("openrouter_request_error", attempt=attempt + 1, error=str(e))
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)
                continue

    raise last_error


async def _call_nvidia(prompt: str) -> str:
    """Send prompt to NVIDIA NIM API (Qwen, etc.)."""
    api_key = getattr(settings, "nvidia_api_key", None)
    if not api_key:
        raise ValueError("NVIDIA_API_KEY not configured")

    model = settings.llm_model or "qwen/qwen2.5-coder-32b-instruct"

    logger.info("nvidia_request_start", model=model, prompt_len=len(prompt))

    url = "https://integrate.api.nvidia.com/v1/chat/completions"

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "top_p": 0.7,
        "max_tokens": 2048,
        "stream": False,
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    last_error = None
    for attempt in range(3):
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(connect=15.0, read=120.0, write=15.0, pool=15.0)) as client:
                resp = await client.post(url, json=payload, headers=headers)

                if resp.status_code == 429:
                    wait_time = (2 ** attempt) * 3
                    logger.warning("nvidia_rate_limited", attempt=attempt + 1, wait=wait_time)
                    if attempt < 2:
                        await asyncio.sleep(wait_time)
                        continue
                    raise Exception("Rate limited - too many requests")

                resp.raise_for_status()
                result = resp.json()

                if "choices" in result and len(result["choices"]) > 0:
                    text = result["choices"][0].get("message", {}).get("content", "")
                    logger.info("nvidia_request_success", response_len=len(text))
                    return text

                raise ValueError(f"NVIDIA response missing content: {result}")

        except httpx.HTTPStatusError as e:
            last_error = e
            if e.response.status_code == 429:
                wait_time = (2 ** attempt) * 3
                logger.warning("nvidia_http_rate_limited", attempt=attempt + 1, wait=wait_time)
                if attempt < 2:
                    await asyncio.sleep(wait_time)
                    continue
        except Exception as e:
            last_error = e
            logger.warning("nvidia_request_error", attempt=attempt + 1, error=str(e))
            if attempt < 2:
                await asyncio.sleep(2 ** attempt)
                continue

    raise last_error


async def _call_llm(prompt: str) -> str:
    """Route to the appropriate LLM based on settings."""
    provider = settings.llm_provider.lower() if settings.llm_provider else "ollama"

    if provider == "google":
        return await _call_google(prompt)
    elif provider == "openrouter":
        return await _call_openrouter(prompt)
    elif provider == "nvidia":
        return await _call_nvidia(prompt)
    else:
        return await _call_ollama(prompt)


async def _call_ollama(prompt: str) -> str:
    """Send prompt to Ollama and return the raw response text."""
    logger.info("ollama_request_start", model=settings.llm_model, host=settings.ollama_host, prompt_len=len(prompt))
    return await _call_ollama_with_retry(prompt)
