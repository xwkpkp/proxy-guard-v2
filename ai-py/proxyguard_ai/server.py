"""proxyguard_ai.server — 研判服务 HTTP 入口。

路由：
  GET  /health   存活检查
  GET  /stats    队列指标 + 已加载插件
  POST /judge    数据面事件入队（立即 202，绝不阻塞调用方）

服务只监听 127.0.0.1；由 Go 控制面调用（docs/contract.md）。
"""
from __future__ import annotations

import logging

from aiohttp import web

from .llm import JudgmentQueue
from .plugins import PluginRegistry

log = logging.getLogger("proxyguard_ai.server")


def _rule_hits_summary(hits: list[dict]) -> str:
    """把契约里的 hits 数组压成一行摘要（进 prompt）。"""
    parts: list[str] = []
    for h in hits[:12]:  # 控制 prompt 体积
        rid = h.get("rule_id", "?")
        sev = h.get("severity", "?")
        parts.append(f"{rid}({sev})")
    return ",".join(parts) if parts else "-"


def create_app(queue: JudgmentQueue, registry: PluginRegistry) -> web.Application:
    app = web.Application()
    app["queue"] = queue
    app["registry"] = registry

    async def health(_req: web.Request) -> web.Response:
        return web.json_response({"ok": True, "service": "proxyguard-ai"})

    async def stats(_req: web.Request) -> web.Response:
        q: JudgmentQueue = app["queue"]
        reg: PluginRegistry = app["registry"]
        return web.json_response({
            "queue": q.metrics(),
            "llm_enabled": q.client is not None,
            "model": q.client.model if q.client else "",
            "plugins": reg.names(),
        })

    async def judge(req: web.Request) -> web.Response:
        """接收数据面事件（Go 转发），异步入队。"""
        try:
            ev = await req.json()
        except Exception:  # noqa: BLE001
            return web.json_response({"error": "bad json"}, status=400)

        sample = ev.get("sample") or ""
        hits = ev.get("hits") or []
        if not sample and not hits:
            return web.json_response({"error": "empty event"}, status=400)

        ok = await app["queue"].put(
            sample=sample,
            rule_hits=_rule_hits_summary(hits),
            ctx=ev.get("ctx", ""),
            target=ev.get("target", ""),
            trace_id=ev.get("trace_id", ""),
            action=ev.get("action_taken", ""),
        )
        # 202：已接受；提交失败（队列满）也返回 202 并在体内说明，避免
        # 让上游产生"重试"预期——研判允许丢弃。
        return web.json_response(
            {"accepted": ok, "queued": ok},
            status=202,
        )

    app.router.add_get("/health", health)
    app.router.add_get("/stats", stats)
    app.router.add_post("/judge", judge)
    return app


def run_app(app: web.Application, listen: str) -> None:
    log.info("研判服务监听 %s", listen)
    web.run_app(app, host=listen.split(":")[0], port=int(listen.split(":")[1]),
                print=None, access_log=None)
