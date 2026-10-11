"""proxyguard_ai.plugins — 插件框架雏形。

设计原则：插件永远运行在旁路（研判链路）上，绝不进数据面关键路径。

发现机制：
  1. 内置插件（本模块内注册）；
  2. 第三方插件：importlib.metadata entry_points，group = "proxyguard_ai.plugins"。

插件接口（鸭子类型，无需继承）：
  name: str                                  插件标识
  prompt_extras(record) -> str | None        为研判追加提示词（可选）
  async on_verdict(record) -> None           研判完成后的钩子（可选）

典型生态用途：把 LLM 确认的恶意样本沉淀为规则 YAML（Rust 数据面下一轮
快照热加载），形成"研判 → 规则 → 检测"的闭环。
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import yaml

log = logging.getLogger("proxyguard_ai.plugins")

ENTRY_POINT_GROUP = "proxyguard_ai.plugins"


@runtime_checkable
class JudgePlugin(Protocol):
    """插件协议。"""

    name: str

    def prompt_extras(self, record: dict) -> str | None:
        """可选：返回追加到研判提示词的文本。"""

    async def on_verdict(self, record: dict) -> None:
        """可选：研判完成后的异步钩子。"""


class RuleSuggester:
    """内置插件：把 LLM 确认的恶意样本沉淀为建议规则（rules/generated/）。

    规则只作为"建议"落盘，由运维审阅后并入正式规则库；数据面不会
    自动加载 generated 目录（防规则投毒路径）。
    """

    name = "rule_suggester"
    #: 同一 (target, attack_type) 只写一次
    _seen: set[tuple[str, str]]

    def __init__(self, out_dir: str = "rules/generated") -> None:
        self.out_dir = Path(out_dir)
        self._seen = set()

    def prompt_extras(self, record: dict) -> str | None:
        return None

    async def on_verdict(self, record: dict) -> None:
        if record.get("llm_verdict") != "malicious":
            return
        target = (record.get("target") or "").strip()
        attack_type = (record.get("attack_type") or "unknown").strip()
        if not target:
            return
        key = (target, attack_type)
        if key in self._seen:
            return
        self._seen.add(key)

        rule = {
            "id": f"suggested_{abs(hash(key)) % 10**8:08d}",
            "name": f"研判建议: {attack_type}",
            "severity": "medium",
            "scope": "request_path",
            "type": "substring",
            "pattern": target,
            "desc": (record.get("reason") or "")[:120],
        }
        await asyncio.to_thread(self._append_rule, rule)

    def _append_rule(self, rule: dict) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        path = self.out_dir / "suggested.yaml"
        data: dict[str, Any] = {"rules": []}
        if path.is_file():
            try:
                loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                if isinstance(loaded, dict) and isinstance(loaded.get("rules"), list):
                    data = loaded
            except Exception as exc:  # noqa: BLE001
                log.warning("读取建议规则失败（将重建）: %s", exc)
        data["rules"].append(rule)
        path.write_text(
            yaml.safe_dump(data, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        log.info("建议规则已写入 %s: %s", path, rule["id"])


class PluginRegistry:
    """插件注册与调度。"""

    def __init__(self, plugins: list[Any] | None = None) -> None:
        self._plugins: list[Any] = list(plugins or [])

    @classmethod
    def discover(cls, builtin: bool = True) -> "PluginRegistry":
        """发现内置 + entry-points 插件。任何插件加载失败不影响服务。"""
        plugins: list[Any] = []
        if builtin:
            plugins.append(RuleSuggester())
        try:
            from importlib.metadata import entry_points

            for ep in entry_points(group=ENTRY_POINT_GROUP):
                try:
                    factory = ep.load()
                    plugins.append(factory() if callable(factory) else factory)
                    log.info("插件加载: %s", ep.name)
                except Exception as exc:  # noqa: BLE001
                    log.warning("插件 %s 加载失败: %s", ep.name, exc)
        except Exception:  # noqa: BLE001
            pass
        return cls(plugins)

    def names(self) -> list[str]:
        return [getattr(p, "name", type(p).__name__) for p in self._plugins]

    def prompt_extras(self, record: dict) -> str:
        parts: list[str] = []
        for p in self._plugins:
            fn = getattr(p, "prompt_extras", None)
            if fn is None:
                continue
            try:
                extra = fn(record)
                if extra:
                    parts.append(str(extra))
            except Exception as exc:  # noqa: BLE001
                log.warning("插件 %s prompt_extras 失败: %s", getattr(p, "name", "?"), exc)
        return "\n".join(parts)

    async def run_on_verdict(self, record: dict) -> None:
        for p in self._plugins:
            fn = getattr(p, "on_verdict", None)
            if fn is None:
                continue
            try:
                await fn(record)
            except Exception as exc:  # noqa: BLE001
                log.warning("插件 %s on_verdict 失败: %s", getattr(p, "name", "?"), exc)
