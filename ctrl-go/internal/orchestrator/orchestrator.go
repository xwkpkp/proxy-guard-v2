// Package orchestrator 组装并驱动 Go 控制面。
//
// 数据流：
//
//	池引擎（抓取/验证/评分） ──快照──▶ Rust 数据面（执行转发/检测/轮换）
//	Rust 事件流 ──SSE──▶ 本层 ──转发──▶ Python 研判（/judge）
//	Python 研判回写 ──▶ 本层 ──增量策略──▶ Rust
//
// 常驻循环：快照推送、事件订阅、指标拉取（管理 API 由 server 包托管）。
package orchestrator

import (
	"context"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/aiclient"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/contract"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/pgconfig"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/pool"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/ruster"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/server"
)

// Options 组装依赖。
type Options struct {
	Cfg    *pgconfig.Config
	Engine *pool.Engine
	Rust   *ruster.Client
	AI     *aiclient.Client
}

// Orchestrator 控制面主编排。
type Orchestrator struct {
	opts    Options
	version atomic.Uint64 // 快照版本（单调递增）
	resnap  chan struct{} // 立即重推触发

	mu           sync.Mutex
	blockTargets map[string]struct{} // 研判封锁的目标（host 或 host+path 前缀）
	recentRules  map[string][]string // trace_id → 命中规则 ID（研判回写时定位规则）
	recentOrder  []string            // recentRules 的 FIFO 顺序（容量限制）
	benignStreak map[string]int      // 规则连续被判 benign 的次数
	weights      map[string]float64  // 规则权重（<1 降权）

	st stats
}

const recentRulesCap = 1000

type stats struct {
	startedAt          time.Time
	eventsReceived     atomic.Int64
	eventsForwarded    atomic.Int64
	verdictsMalicious  atomic.Int64
	verdictsSuspicious atomic.Int64
	verdictsBenign     atomic.Int64
	snapshotOK         atomic.Int64
	snapshotFail       atomic.Int64
	lastSnapshotVer    atomic.Uint64
	lastEventTS        atomic.Int64

	metricsMu   sync.Mutex
	lastMetrics contract.MetricBatch
	metricsSeen bool
}

// New 创建编排器。
func New(opts Options) *Orchestrator {
	return &Orchestrator{
		opts:         opts,
		resnap:       make(chan struct{}, 1),
		blockTargets: make(map[string]struct{}),
		recentRules:  make(map[string][]string),
		benignStreak: make(map[string]int),
		weights:      make(map[string]float64),
		st:           stats{startedAt: time.Now()},
	}
}

// Run 启动全部循环并阻塞直到 ctx 取消。
func (o *Orchestrator) Run(ctx context.Context) error {
	if err := o.opts.Engine.Start(ctx); err != nil {
		return err
	}
	srv, err := server.Start(o.opts.Cfg.Ctrl.APIListen, server.Deps{
		Stats:     o.Stats,
		OnVerdict: o.HandleVerdict,
	})
	if err != nil {
		o.opts.Engine.Stop()
		return err
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); o.snapshotLoop(ctx) }()
	go func() { defer wg.Done(); o.eventsLoop(ctx) }()
	go func() { defer wg.Done(); o.metricsLoop(ctx) }()

	<-ctx.Done()
	log.Printf("[control] 收到退出信号，停止中…")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	o.opts.Engine.Stop()
	wg.Wait()
	return nil
}

// ---------------------------------------------------------------------------
// 快照
// ---------------------------------------------------------------------------

func (o *Orchestrator) snapshotLoop(ctx context.Context) {
	interval := time.Duration(o.opts.Cfg.Ctrl.SnapshotIntervalS) * time.Second
	t := time.NewTicker(interval)
	defer t.Stop()

	o.pushSnapshot(ctx) // 启动立即推一次（数据面可能未就绪，失败会在下一轮重试）
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			o.pushSnapshot(ctx)
		case <-o.resnap:
			o.pushSnapshot(ctx)
		}
	}
}

// triggerResnap 请求立即重推快照（非阻塞；已有待处理请求时合并）。
func (o *Orchestrator) triggerResnap() {
	select {
	case o.resnap <- struct{}{}:
	default:
	}
}

func (o *Orchestrator) pushSnapshot(ctx context.Context) {
	snap := o.buildSnapshot()
	pushCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	ack, err := o.opts.Rust.PushSnapshot(pushCtx, snap)
	if err != nil {
		o.st.snapshotFail.Add(1)
		log.Printf("[control] 快照推送失败（数据面未就绪？）: %v", err)
		return
	}
	if !ack.Accepted {
		o.st.snapshotFail.Add(1)
		log.Printf("[control] 快照 v%d 被拒: %s（数据面当前 v%d）", snap.Version, ack.Reason, ack.CurrentVersion)
		return
	}
	o.st.snapshotOK.Add(1)
	o.st.lastSnapshotVer.Store(snap.Version)
	log.Printf("[control] 快照 v%d 已生效: 出口 %d 个", snap.Version, len(snap.Pool))
}

// buildSnapshot 从池与配置生成全量快照。仅把 StatusAlive 的出口发往数据面。
func (o *Orchestrator) buildSnapshot() contract.ConfigSnapshot {
	c := o.opts.Cfg

	proxies := o.opts.Engine.Pool().List()
	alive := make([]string, 0, len(proxies))
	for _, p := range proxies {
		if p.Status == pool.StatusAlive {
			alive = append(alive, p.ID())
		}
	}

	return contract.ConfigSnapshot{
		Version:  o.version.Add(1),
		IssuedAt: time.Now().Unix(),
		Pool:     alive,
		Routing: contract.RoutingTable{
			Mode:           c.Routing.Mode,
			DirectDomains:  orEmpty(c.Routing.DirectDomains),
			DirectSuffixes: orEmpty(c.Routing.DirectSuffixes),
			ProxyDomains:   orEmpty(c.Routing.ProxyDomains),
		},
		Policy: contract.Policy{
			Rotation: contract.RotationPolicy{
				Strategy:        c.Rotator.Strategy,
				SwitchIntervalS: c.Rotator.SwitchInterval,
				MaxFailures:     c.Rotator.MaxFailures,
				CooldownS:       c.Rotator.Cooldown,
			},
			ScanRequest:         c.Shield.ScanRequest,
			ScanResponse:        c.Shield.ScanResponse,
			BlockOnDetect:       c.Shield.BlockOnDetect,
			SwitchOnDetect:      c.Shield.SwitchOnDetect,
			MITMEnabled:         c.Shield.MITMEnabled,
			MaxBodyScan:         c.Shield.MaxBodyScan,
			CircuitThreshold:    c.Shield.CircuitThreshold,
			CircuitCooldownS:    c.Shield.CircuitCooldown,
			MaxConcurrent:       c.Shield.MaxConcurrent,
			RedlineEnabled:      c.Shield.RedlineEnabled,
			SSRFProtect:         c.Shield.SSRFProtect,
			CSPInject:           c.Shield.CSPInject,
			DetectInjection:     c.Shield.DetectInjection,
			LLMMaliciousAction:  "block",
			LLMSuspiciousAction: "log_only",
		},
		// 出口黑名单（验证中发现内容注入的代理）由后续版本填充；
		// 机制已保留，当前为空数组（契约要求空集合而非 null）。
		Blacklist: []string{},
	}
}

// orEmpty 保证切片序列化为 `[]` 而非 `null`（契约规范：空集合用数组表示）。
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---------------------------------------------------------------------------
// 事件流（Rust → Go → Python）
// ---------------------------------------------------------------------------

func (o *Orchestrator) eventsLoop(ctx context.Context) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for ctx.Err() == nil {
		ch, err := o.opts.Rust.WatchEvents(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[control] 事件流连接失败: %v（%s 后重试）", err, backoff)
			sleepCtx(ctx, backoff)
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = time.Second
		log.Printf("[control] 事件流已连接")

		for ev := range ch {
			o.handleEvent(ctx, ev)
		}
		if ctx.Err() != nil {
			return
		}
		log.Printf("[control] 事件流断开，准备重连")
		sleepCtx(ctx, backoff)
	}
}

func (o *Orchestrator) handleEvent(ctx context.Context, ev contract.ThreatEvent) {
	o.st.eventsReceived.Add(1)
	o.st.lastEventTS.Store(ev.TS)
	o.recordRules(ev.TraceID, ev.Hits)

	if ev.Kind != contract.KindDetect {
		log.Printf("[control] 事件 %s kind=%s action=%s", ev.TraceID, ev.Kind, ev.ActionTaken)
		return
	}

	hits := ""
	for i, h := range ev.Hits {
		if i > 0 {
			hits += ","
		}
		hits += h.RuleID
	}
	log.Printf("[control] 检测事件 %s ctx=%s target=%s action=%s hits=%s",
		ev.TraceID, ev.Ctx, ev.Target, ev.ActionTaken, hits)

	// 转发 Python 研判（异步旁路；失败只记日志，绝不阻塞事件消费）。
	if len(ev.Sample) > 0 {
		fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := o.opts.AI.Judge(fctx, ev); err != nil {
			log.Printf("[control] 研判转发失败（AI 层离线？）: %v", err)
		} else {
			o.st.eventsForwarded.Add(1)
		}
	}
}

// ---------------------------------------------------------------------------
// 指标
// ---------------------------------------------------------------------------

func (o *Orchestrator) metricsLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			mctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			m, err := o.opts.Rust.Metrics(mctx)
			cancel()
			if err != nil {
				continue
			}
			o.st.metricsMu.Lock()
			o.st.lastMetrics = m
			o.st.metricsSeen = true
			o.st.metricsMu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// 研判回写
// ---------------------------------------------------------------------------

// HandleVerdict 处理 Python 回写的研判结果（由 server 包调用）。
func (o *Orchestrator) HandleVerdict(v contract.VerdictUpdate) {
	log.Printf("[control] 研判回写 trace=%s verdict=%s type=%s conf=%.2f model=%s",
		v.TraceID, v.Verdict, v.AttackType, v.Confidence, v.Model)

	var delta *contract.PolicyDelta

	o.mu.Lock()
	switch v.Verdict {
	case contract.VerdictMalicious:
		o.st.verdictsMalicious.Add(1)
		if v.Target != "" {
			o.blockTargets[v.Target] = struct{}{}
		}
		// 恶意确认：相关规则的误报计数清零
		for _, id := range o.recentRules[v.TraceID] {
			o.benignStreak[id] = 0
		}
		delta = o.buildDeltaLocked()

	case contract.VerdictBenign:
		o.st.verdictsBenign.Add(1)
		// 误报纠正：同一规则连续 3 次被判 benign → 权重降到 0.5
		changed := false
		for _, id := range o.recentRules[v.TraceID] {
			o.benignStreak[id]++
			if o.benignStreak[id] >= 3 && o.weights[id] != 0.5 {
				o.weights[id] = 0.5
				changed = true
			}
		}
		if changed {
			delta = o.buildDeltaLocked()
		}

	case contract.VerdictSuspicious:
		o.st.verdictsSuspicious.Add(1)
	}
	o.mu.Unlock()

	if delta != nil {
		go o.pushPolicyDelta(delta)
	}
}

func (o *Orchestrator) pushPolicyDelta(delta *contract.PolicyDelta) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := o.opts.Rust.PushPolicy(ctx, *delta); err != nil {
		log.Printf("[control] 策略增量下发失败: %v", err)
		return
	}
	log.Printf("[control] 策略增量已下发: block_targets=%d rule_weights=%d",
		len(delta.BlockTargets), len(delta.RuleWeight))
}

// buildDeltaLocked 组装当前增量策略（调用方持锁）。
func (o *Orchestrator) buildDeltaLocked() *contract.PolicyDelta {
	block := make([]string, 0, len(o.blockTargets))
	for t := range o.blockTargets {
		block = append(block, t)
	}
	sort.Strings(block)

	w := make(map[string]float64, len(o.weights))
	for k, v := range o.weights {
		w[k] = v
	}
	return &contract.PolicyDelta{
		BaseVersion:  o.version.Load(),
		BlockTargets: block,
		RuleWeight:   w,
	}
}

func (o *Orchestrator) recordRules(traceID string, hits []contract.RuleHit) {
	if traceID == "" || len(hits) == 0 {
		return
	}
	ids := make([]string, 0, len(hits))
	for _, h := range hits {
		ids = append(ids, h.RuleID)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, exists := o.recentRules[traceID]; !exists {
		o.recentOrder = append(o.recentOrder, traceID)
	}
	o.recentRules[traceID] = ids
	for len(o.recentOrder) > recentRulesCap {
		old := o.recentOrder[0]
		o.recentOrder = o.recentOrder[1:]
		delete(o.recentRules, old)
	}
}

// ---------------------------------------------------------------------------
// 统计
// ---------------------------------------------------------------------------

// Stats 汇总 Go 控制面状态（server 包 /api/stats 调用）。
func (o *Orchestrator) Stats() any {
	pst := o.opts.Engine.Pool().Stats(pool.Filter{})

	o.st.metricsMu.Lock()
	m := o.st.lastMetrics
	seen := o.st.metricsSeen
	o.st.metricsMu.Unlock()

	dp := map[string]any{"reachable": seen}
	if seen {
		dp["metrics"] = m
	}

	o.mu.Lock()
	blockCount := len(o.blockTargets)
	weights := make(map[string]float64, len(o.weights))
	for k, v := range o.weights {
		weights[k] = v
	}
	o.mu.Unlock()

	return map[string]any{
		"contract_version": contract.Version,
		"uptime_s":         int64(time.Since(o.st.startedAt).Seconds()),
		"go_pool": map[string]any{
			"total":          pst.Total,
			"alive":          pst.Alive,
			"pending":        pst.Pending,
			"dead":           pst.Dead,
			"eligible":       pst.Eligible,
			"avg_latency_ms": pst.AvgLatency.Milliseconds(),
		},
		"data_plane": dp,
		"events": map[string]any{
			"received":  o.st.eventsReceived.Load(),
			"forwarded": o.st.eventsForwarded.Load(),
			"last_ts":   o.st.lastEventTS.Load(),
		},
		"verdicts": map[string]any{
			"malicious":  o.st.verdictsMalicious.Load(),
			"suspicious": o.st.verdictsSuspicious.Load(),
			"benign":     o.st.verdictsBenign.Load(),
		},
		"snapshot": map[string]any{
			"ok":      o.st.snapshotOK.Load(),
			"fail":    o.st.snapshotFail.Load(),
			"version": o.st.lastSnapshotVer.Load(),
		},
		"block_targets": blockCount,
		"rule_weights":  weights,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
