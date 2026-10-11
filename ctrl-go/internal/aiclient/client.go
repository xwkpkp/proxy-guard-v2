// Package aiclient 把数据面事件转发到 Python AI 层的 /judge 端点。
//
// 约定：Python 收下即返回 202（异步入队研判）；研判结果由 Python 主动回写
// Go 的 /internal/verdict（见 docs/contract.md）。转发失败只记日志，
// 绝不阻塞事件消费（AI 层永远不进关键路径）。
package aiclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/contract"
)

// Client 访问 Python 研判服务。
type Client struct {
	judgeURL  string
	healthURL string
	httpc     *http.Client
}

// New 创建客户端。
func New(aiURL string) *Client {
	base := strings.TrimRight(aiURL, "/")
	return &Client{
		judgeURL:  base + "/judge",
		healthURL: base + "/health",
		httpc:     &http.Client{Timeout: 5 * time.Second},
	}
}

// Judge 提交事件入队，期望 202 Accepted。
func (c *Client) Judge(ctx context.Context, ev contract.ThreatEvent) error {
	buf, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.judgeURL, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("judge: status %d", resp.StatusCode)
	}
	return nil
}

// Health 探测 Python 服务是否在线（用于 stats 聚合）。
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.healthURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ai health: status %d", resp.StatusCode)
	}
	return nil
}
