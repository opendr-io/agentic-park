"""Shared LLM utilities for streaming and response handling."""

import os
import configparser
from pathlib import Path

# Short names -> full model IDs
MODEL_ALIASES = {
    'opus': 'claude-opus-4-0-20250514',
    'sonnet': 'claude-sonnet-4-5-20250929',
    'haiku': 'claude-haiku-4-5-20250929',
}

# Cache parsed config
_config_cache = None


def _load_config():
    """Load model config from log_loader_config.ini (cached)."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    config = configparser.ConfigParser()
    config_path = Path('log_loader_config.ini')
    if config_path.exists():
        config.read(config_path)

    _config_cache = config
    return config


def resolve_model(name):
    """Resolve a short model name (opus/sonnet/haiku) or return as-is.

    Args:
        name: Short name like 'opus' or full model ID

    Returns:
        Full model ID string
    """
    return MODEL_ALIASES.get(name.lower().strip(), name)


def get_llm(tools=None, temperature=0, model=None, max_tokens=None):
    """Create a ChatAnthropic instance with standard config.

    Model resolution order:
    1. Explicit `model` parameter (for callers like alert_memory that hardcode Haiku)
    2. CLAUDE_MODEL environment variable
    3. [LLM] model in log_loader_config.ini
    4. Default: sonnet

    Args:
        tools: Optional list of tool schemas to bind
        temperature: LLM temperature (default 0)
        model: Model name override — short name (opus/sonnet/haiku) or full ID
        max_tokens: Optional max tokens limit

    Returns:
        ChatAnthropic instance, with tools bound if provided
    """
    from langchain_anthropic import ChatAnthropic

    if model is None:
        # Check env var first, then config file
        model = os.getenv('CLAUDE_MODEL')
        if not model:
            config = _load_config()
            model = config.get('LLM', 'model', fallback='sonnet')

    model = resolve_model(model)
    api_key = os.getenv('ANTHROPIC_API_KEY')

    kwargs = dict(model=model, anthropic_api_key=api_key, temperature=temperature)
    if max_tokens is not None:
        kwargs['max_tokens'] = max_tokens

    llm = ChatAnthropic(**kwargs)
    if tools:
        llm = llm.bind_tools(tools)
    return llm


def _extract_text(content):
    """Extract plain text from a chunk's content.

    LangChain Anthropic streaming chunks return content as either:
    - a plain string
    - a list of content blocks: [{'text': '...', 'type': 'text', 'index': 0}]
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict) and block.get('type') == 'text':
                parts.append(block.get('text', ''))
            elif isinstance(block, str):
                parts.append(block)
        return ''.join(parts)
    return str(content)


def stream_response(llm, messages, silent=False):
    """Stream LLM response, printing tokens as they arrive.

    Returns the full AIMessage with .content and .tool_calls intact,
    so it works as a drop-in replacement for llm.invoke(messages).

    Args:
        llm: LangChain ChatAnthropic instance (with or without tools bound)
        messages: List of messages to send
        silent: If True, use .invoke() instead (no streaming for background processing)

    Returns:
        AIMessage — identical to what .invoke() would return
    """
    if silent:
        return llm.invoke(messages)

    chunks = []
    for chunk in llm.stream(messages):
        if chunk.content:
            text = _extract_text(chunk.content)
            if text:
                print(text, end='', flush=True)
        chunks.append(chunk)
    print()  # newline after streamed output

    # Combine chunks into a single AIMessage
    # LangChain's AIMessageChunk.__add__ merges content and tool_calls
    full = chunks[0]
    for chunk in chunks[1:]:
        full = full + chunk

    # Normalize .content to a plain string so callers get the same type
    # as .invoke() returns. Streaming chunks keep content as a list of
    # content blocks; .invoke() returns a flat string.
    if not isinstance(full.content, str):
        full.content = _extract_text(full.content)

    return full
