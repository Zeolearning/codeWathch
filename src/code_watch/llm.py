from __future__ import annotations

from langchain_openai import ChatOpenAI

from code_watch.config import CodeWatchConfig


def get_llm(config: CodeWatchConfig, *, temperature: float = 0.0) -> ChatOpenAI:
    """Shared LLM client factory.

    Every subsystem (analysis agent, rule-gen-prep agent, rule generator,
    structured-output extraction) should obtain its model through this helper
    so configuration stays in one place. The model is OpenAI-compatible
    (the live .env points at an OpenAI-compatible endpoint such as DeepSeek).
    """
    return ChatOpenAI(
        model=config.model,
        temperature=temperature,
        **({"base_url": config.openai_base_url} if config.openai_base_url else {}),
        **({"api_key": config.openai_api_key} if config.openai_api_key else {}),
    )
