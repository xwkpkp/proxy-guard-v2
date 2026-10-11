// Package ruster 是 Rust 数据面控制口的客户端。
//
// 方向：
//
//	PushSnapshot / PushPolicy —— Go → Rust（配置与策略下发）
//	WatchEvents                —— Rust → Go（SSE 事件流，长连接）
//	Metrics / Health           —— 拉取状态
//
// 传输为 JSON over 127.0.0.1（见 docs/contract.md）。token 为空时不带认证头
// （仅限本地开发）；生产配置必须设置 ctrl.ctrl_token。
package ruster

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/contract"
)

// Client 访问 Rust 数据面的控制口。
type Client struct {
	baseURL string
	token   string
	httpc   *http.Client
	// streamClient 用于长连接的 SSE（无全局超时）。
	streamClient *http.Client
}

// New 创建客户端。
func New(baseURL, token string) *Client {
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		token:        token,
		httpc:        &http.Client{Timeout: 10 * time.Second},
		streamClient: &http.Client{},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.httpc.Do(req)
}

// Health 检查数据面控制口存活。
func (c *Client) Health(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, contract.PathHealth, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health: status %d", resp.StatusCode)
	}
	return nil
}

// PushSnapshot 下发全量快照，返回数据面应答。
func (c *Client) PushSnapshot(ctx context.Context, snap contract.ConfigSnapshot) (contract.SnapshotAck, error) {
	var ack contract.SnapshotAck
	resp, err := c.do(ctx, http.MethodPost, contract.PathSnapshot, snap)
	if err != nil {
		return ack, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ack, fmt.Errorf("snapshot: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return ack, fmt.Errorf("snapshot ack: %w", err)
	}
	return ack, nil
}

// PushPolicy 下发增量策略。
func (c *Client) PushPolicy(ctx context.Context, d contract.PolicyDelta) (contract.Ack, error) {
	var ack contract.Ack
	resp, err := c.do(ctx, http.MethodPost, contract.PathPolicy, d)
	if err != nil {
		return ack, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ack, fmt.Errorf("policy: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		return ack, fmt.Errorf("policy ack: %w", err)
	}
	return ack, nil
}

// Metrics 拉取指标快照。
func (c *Client) Metrics(ctx context.Context) (contract.MetricBatch, error) {
	var m contract.MetricBatch
	resp, err := c.do(ctx, http.MethodGet, contract.PathMetrics, nil)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return m, fmt.Errorf("metrics: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return m, fmt.Errorf("metrics decode: %w", err)
	}
	return m, nil
}

// WatchEvents 订阅 SSE 事件流；连接断开时返回的 channel 关闭。
// 重连策略由调用方负责（指数退避，见 docs/contract.md）。
func (c *Client) WatchEvents(ctx context.Context) (<-chan contract.ThreatEvent, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+contract.PathEvents, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.streamClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("events: status %d", resp.StatusCode)
	}

	ch := make(chan contract.ThreatEvent, 64)
	go func() {
		defer resp.Body.Close()
		defer close(ch)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if payload == "" {
				continue
			}
			var ev contract.ThreatEvent
			if err := json.Unmarshal([]byte(payload), &ev); err != nil {
				continue // 单条坏数据不中断流
			}
			select {
			case ch <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}
