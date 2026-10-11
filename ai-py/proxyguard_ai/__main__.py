"""proxyguard_ai 服务入口。

用法：
    python -m proxyguard_ai [-c config.yaml] [--listen 127.0.0.1:8892] [--go-api http://127.0.0.1:8891]

配置来源：config.yaml 的 llm 段 + ctrl 段。
说明：LLM 密钥在本地进程内读取（不经过网络分发）；数据面/策略配置仍由
Go 控制面统一下发（本服务只读 llm/ctrl 两个本地段）。
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
import yaml
from aiohttp import web

from .llm import JudgmentQueue, LLMClient
from .plugins import PluginRegistry
from .server import create_app, run_app

log = logging.getLogger("proxyguard_ai")


def _load_config(path: Path) -> dict:
    if not path.is_file():
        log.warning("配置文件不存在: %s（使用内置默认）", path)
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        log.error("配置解析失败: %s", exc)
        return {}


def _hostport_from_url(url: str) -> str:
    p = urlparse(url if "://" in url else "http://" + url)
    host = p.hostname or "127.0.0.1"
    port = p.port or 8892
    return f"{host}:{port}"


def main() -> None:
    ap = argparse.ArgumentParser(prog="proxyguard_ai")
    ap.add_argument("-c", "--config", default="config.yaml", help="config.yaml 路径")
    ap.add_argument("--listen", default="", help="监听地址（默认取 ctrl.ai_url）")
    ap.add_argument("--go-api", default="", help="Go 管理 API（默认取 ctrl.api_listen）")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )

    cfg = _load_config(Path(args.config))
    llm_cfg = cfg.get("llm") or {}
    ctrl = cfg.get("ctrl") or {}

    listen = args.listen or _hostport_from_url(ctrl.get("ai_url", "http://127.0.0.1:8892"))
    go_api = args.go_api or ("http://" + str(ctrl.get("api_listen", "127.0.0.1:8891")))

    client: LLMClient | None = None
    if llm_cfg.get("enabled"):
        if not llm_cfg.get("api_key"):
            log.warning("llm.enabled=true 但 api_key 为空，研判队列空跑")
        else:
            client = LLMClient(
                base_url=llm_cfg.get("base_url", "https://api.openai.com"),
                api_key=llm_cfg.get("api_key", ""),
                model=llm_cfg.get("model", "gpt-4o-mini"),
                proxy=llm_cfg.get("proxy", ""),
                timeout=float(llm_cfg.get("timeout", 30)),
            )

    registry = PluginRegistry.discover()

    async def on_result(record: dict) -> None:
        """研判结果出口：插件钩子 + 回写 Go 控制面。"""
        await registry.run_on_verdict(record)

        payload = {
            "trace_id": record.get("trace_id", ""),
            "verdict": record.get("llm_verdict", ""),
            "attack_type": record.get("attack_type", ""),
            "reason": record.get("reason", ""),
            "confidence": record.get("confidence", 0),
            "ts": int(record.get("ts", 0)),
            "model": client.model if client else "",
            "target": record.get("target", ""),
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{go_api}/internal/verdict",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status != 200:
                        log.warning("verdict 回写 Go 失败: HTTP %d", resp.status)
        except Exception as exc:  # noqa: BLE001
            log.warning("verdict 回写 Go 异常（控制面离线？）: %s", exc)

    queue = JudgmentQueue(
        client=client,
        output_path=llm_cfg.get("output_path", "llm_judgments.jsonl"),
        max_concurrent=int(llm_cfg.get("max_concurrent", 2)),
        on_result=on_result,
    )

    app = create_app(queue, registry)

    async def _startup(_app: web.Application) -> None:
        await queue.start()

    async def _cleanup(_app: web.Application) -> None:
        await queue.stop()

    app.on_startup.append(_startup)
    app.on_cleanup.append(_cleanup)

    log.info("go_api=%s plugins=%s llm=%s", go_api, registry.names(), client.model if client else "off")
    run_app(app, listen)


if __name__ == "__main__":
    sys.exit(main())
