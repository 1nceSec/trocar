import json
from typing import AsyncIterator

from tools import TOOL_DEFINITIONS


async def stream_chat(
    *,
    provider: str,
    api_key: str,
    base_url: str,
    model: str,
    max_tokens: int,
    system: str,
    messages: list[dict],
    tools: bool = True,
    thinking_level: str = "",
) -> dict:
    """Run one LLM turn. Returns the full response message dict.
    For Anthropic: handles text + tool_use content blocks.
    For OpenAI: handles content + tool_calls.
    """
    if provider == "openai":
        return await _chat_openai(api_key, base_url, model, max_tokens, system, messages, tools, thinking_level)
    return await _chat_anthropic(api_key, base_url, model, max_tokens, system, messages, tools, thinking_level)


async def stream_text(
    *,
    provider: str,
    api_key: str,
    base_url: str,
    model: str,
    max_tokens: int,
    system: str,
    messages: list[dict],
) -> AsyncIterator[str]:
    """Stream text-only completion (no tool use). Used for legacy/fallback."""
    if provider == "openai":
        async for chunk in _stream_openai_text(api_key, base_url, model, max_tokens, system, messages):
            yield chunk
    else:
        async for chunk in _stream_anthropic_text(api_key, base_url, model, max_tokens, system, messages):
            yield chunk


THINKING_BUDGETS = {
    "low": 2048,
    "medium": 8192,
    "high": 32768,
    "xhigh": 65536,
    "max": 128000,
}


async def _chat_anthropic(api_key, base_url, model, max_tokens, system, messages, use_tools, thinking_level=""):
    import anthropic

    kwargs = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    client = anthropic.AsyncAnthropic(**kwargs)

    budget = THINKING_BUDGETS.get(thinking_level, 0)

    call_kwargs = {
        "model": model,
        "max_tokens": max(max_tokens, budget + max_tokens) if budget else max_tokens,
        "system": system,
        "messages": messages,
    }
    if budget:
        call_kwargs["thinking"] = {"type": "enabled", "budget_tokens": budget}
    if use_tools:
        call_kwargs["tools"] = TOOL_DEFINITIONS

    response = await client.messages.create(**call_kwargs)

    text_parts = []
    tool_calls = []
    for block in response.content:
        if block.type == "thinking":
            continue
        elif block.type == "text":
            text_parts.append(block.text)
        elif block.type == "tool_use":
            tool_calls.append({
                "id": block.id,
                "name": block.name,
                "input": block.input,
            })

    raw_content = []
    for b in response.content:
        if b.type == "thinking":
            raw_content.append({"type": "thinking", "thinking": b.thinking})
        elif b.type == "text":
            raw_content.append({"type": "text", "text": b.text})
        elif b.type == "tool_use":
            raw_content.append({"type": "tool_use", "id": b.id, "name": b.name, "input": b.input})

    return {
        "text": "\n".join(text_parts),
        "tool_calls": tool_calls,
        "stop_reason": response.stop_reason,
        "raw_content": raw_content,
    }


async def _chat_openai(api_key, base_url, model, max_tokens, system, messages, use_tools, thinking_level=""):
    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("openai package not installed. Run: pip install openai")

    kwargs = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    client = AsyncOpenAI(**kwargs)

    all_messages = [{"role": "system", "content": system}] + messages

    call_kwargs = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": all_messages,
    }
    if thinking_level:
        effort_map = {"low": "low", "medium": "medium", "high": "high", "xhigh": "high", "max": "high"}
        call_kwargs["reasoning_effort"] = effort_map.get(thinking_level, "medium")
    if use_tools:
        call_kwargs["tools"] = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in TOOL_DEFINITIONS
        ]

    response = await client.chat.completions.create(**call_kwargs)
    choice = response.choices[0]

    tool_calls = []
    if choice.message.tool_calls:
        for tc in choice.message.tool_calls:
            tool_calls.append({
                "id": tc.id,
                "name": tc.function.name,
                "input": json.loads(tc.function.arguments),
            })

    return {
        "text": choice.message.content or "",
        "tool_calls": tool_calls,
        "stop_reason": choice.finish_reason,
    }


def build_tool_result_anthropic(tool_calls_results: list[dict]) -> dict:
    """Build an Anthropic tool_result message."""
    return {
        "role": "user",
        "content": [
            {
                "type": "tool_result",
                "tool_use_id": r["id"],
                "content": r["output"],
            }
            for r in tool_calls_results
        ],
    }


def build_tool_result_openai(tool_calls_results: list[dict]) -> list[dict]:
    """Build OpenAI tool result messages."""
    return [
        {
            "role": "tool",
            "tool_call_id": r["id"],
            "content": r["output"],
        }
        for r in tool_calls_results
    ]


async def _stream_anthropic_text(api_key, base_url, model, max_tokens, system, messages):
    import anthropic
    kwargs = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    client = anthropic.AsyncAnthropic(**kwargs)
    async with client.messages.stream(
        model=model, max_tokens=max_tokens, system=system, messages=messages,
    ) as stream:
        async for text in stream.text_stream:
            yield text


async def _stream_openai_text(api_key, base_url, model, max_tokens, system, messages):
    try:
        from openai import AsyncOpenAI
    except ImportError:
        raise RuntimeError("openai package not installed. Run: pip install openai")
    kwargs = {"api_key": api_key}
    if base_url:
        kwargs["base_url"] = base_url
    client = AsyncOpenAI(**kwargs)
    all_messages = [{"role": "system", "content": system}] + messages
    stream = await client.chat.completions.create(
        model=model, max_tokens=max_tokens, messages=all_messages, stream=True,
    )
    async for chunk in stream:
        if chunk.choices and chunk.choices[0].delta.content:
            yield chunk.choices[0].delta.content
