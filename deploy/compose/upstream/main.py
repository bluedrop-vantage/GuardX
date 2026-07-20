"""Fake OpenAI-compatible upstream. M0 demo only."""
from fastapi import FastAPI, Request

app = FastAPI()


@app.post("/v1/chat/completions")
async def completions(req: Request) -> dict:
    body = await req.json()
    messages = body.get("messages", [])
    last = messages[-1]["content"] if messages else ""
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "model": body.get("model", "fake-1"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"[fake upstream echo] {last[:200]}",
                },
                "finish_reason": "stop",
            }
        ],
    }


@app.get("/healthz")
def health() -> dict:
    return {"status": "ok"}
