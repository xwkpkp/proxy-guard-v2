"""端到端（无网络）测试：/judge → 队列 → 研判 → JSONL + 回写回调 + 插件。

运行：python tests/test_flow.py
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from aiohttp.test_utils import TestClient, TestServer

from proxyguard_ai.llm import JudgmentQueue
from proxyguard_ai.plugins import PluginRegistry, RuleSuggester
from proxyguard_ai.server import create_app


class MockLLM:
    """固定判 malicious 的 mock 客户端。"""

    model = "mock-model"

    async def analyze_threat(self, sample, rule_hits, ctx, target, action=""):  # noqa: ARG002
        return {
            "verdict": "malicious",
            "attack_type": "mock_xss",
            "reason": "mock 判定",
            "confidence": 0.9,
        }


async def test_queue_flow(tmp: Path) -> None:
    """判别链路：put → worker → JSONL + on_result 回调。"""
    got: list[dict] = []

    async def on_result(record: dict) -> None:
        got.append(record)

    q = JudgmentQueue(
        client=MockLLM(),
        output_path=str(tmp / "out.jsonl"),
        max_concurrent=1,
        on_result=on_result,
    )
    await q.start()
    ok = await q.put(
        sample="<script>eval(function(p,a,c,k,e,d)...)</script>",
        rule_hits="js_packer_eval(high)",
        ctx="response",
        target="evil.example/x.js",
        trace_id="pg-test-1",
        action="blocked",
    )
    assert ok, "入队应成功"
    await asyncio.sleep(0.6)  # 等 worker 消费
    await q.stop()

    assert len(got) == 1, f"回调应收 1 条，实际 {len(got)}"
    rec = got[0]
    assert rec["llm_verdict"] == "malicious"
    assert rec["trace_id"] == "pg-test-1"
    assert rec["target"] == "evil.example/x.js"

    lines = (tmp / "out.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1, f"JSONL 应 1 行，实际 {len(lines)}"
    print("PASS: 队列全链路（put → 研判 → JSONL + 回调）")


async def test_queue_overflow(tmp: Path) -> None:
    """有界队列：满则丢弃（不阻塞、不异常）。"""
    q = JudgmentQueue(
        client=MockLLM(),
        output_path=str(tmp / "overflow.jsonl"),
        max_concurrent=1,
    )  # 不 start：队列只进不出，验证丢弃语义
    accepted = 0
    for i in range(500):
        if await q.put("x", "r", "ctx", "t", trace_id=f"t{i}"):
            accepted += 1
    overflow_ok = await q.put("x", "r", "ctx", "t", trace_id="overflow")
    assert accepted == 500, f"应接受 500 条，实际 {accepted}"
    assert overflow_ok is False, "第 501 条应被丢弃"
    print("PASS: 队列满丢弃语义")


async def test_server_endpoints(tmp: Path) -> None:
    """HTTP 端点：/health + /judge（202）+ /stats。"""
    got: list[dict] = []

    async def on_result(record: dict) -> None:
        got.append(record)

    q = JudgmentQueue(
        client=MockLLM(),
        output_path=str(tmp / "server.jsonl"),
        max_concurrent=1,
        on_result=on_result,
    )
    registry = PluginRegistry()
    app = create_app(q, registry)
    await q.start()  # 启动 worker，否则队列只进不出

    async with TestClient(TestServer(app)) as client:
        r = await client.get("/health")
        assert r.status == 200
        body = await r.json()
        assert body["ok"] is True

        r = await client.get("/stats")
        assert r.status == 200
        stats = await r.json()
        assert stats["llm_enabled"] is True

        r = await client.post("/judge", json={
            "trace_id": "pg-http-1",
            "ts": 1,
            "kind": "detect",
            "ctx": "request",
            "target": "victim.example/login",
            "hits": [{"rule_id": "sqli_union", "severity": "high"}],
            "sample": "1 UNION SELECT ...",
            "action_taken": "blocked",
        })
        assert r.status == 202, f"/judge 应 202，实际 {r.status}"
        jbody = await r.json()
        assert jbody["accepted"] is True

        r = await client.post("/judge", json={"bogus": True})
        assert r.status == 400

    await asyncio.sleep(0.3)
    await q.stop()
    assert len(got) >= 1, "HTTP 入队的事件应被后台消费"
    print("PASS: /health + /judge(202) + /stats 端点")


async def test_rule_suggester_plugin(tmp: Path) -> None:
    """插件：malicious 研判 → 建议规则写入 rules/generated/。"""
    out_dir = tmp / "rules" / "generated"
    plugin = RuleSuggester(out_dir=str(out_dir))
    await plugin.on_verdict({
        "llm_verdict": "malicious",
        "target": "evil.example/x.js",
        "attack_type": "mock_xss",
        "reason": "测试",
    })
    path = out_dir / "suggested.yaml"
    assert path.is_file(), "建议规则文件应生成"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert len(data["rules"]) == 1

    # 重复 target 不重复写入
    await plugin.on_verdict({
        "llm_verdict": "malicious",
        "target": "evil.example/x.js",
        "attack_type": "mock_xss",
    })
    data2 = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert len(data2["rules"]) == 1, "同 (target, attack_type) 不应重复写入"
    print("PASS: RuleSuggester 插件（研判 → 建议规则）")


async def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        await test_queue_flow(tmp)
        await test_queue_overflow(tmp)
        await test_server_endpoints(tmp)
        await test_rule_suggester_plugin(tmp)
    print("\n全部通过 (4/4)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
