// Package server 提供 Go 控制面的管理 API。
//
//	GET  /healthz            存活检查
//	GET  /api/stats          汇总统计（池 + 数据面指标 + 研判计数）
//	POST /internal/verdict   研判回写入口（Python → Go）
//
// 管理 API 只服务运维与联调；数据面（Rust）不依赖它。
package server

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/contract"
)

// Deps 由 orchestrator 注入的回调。
type Deps struct {
	Stats     func() any                   // 汇总统计
	OnVerdict func(contract.VerdictUpdate) // 研判回写处理
}

// Start 启动管理 API（非阻塞），返回 server 句柄供优雅关闭。
func Start(listen string, deps Deps) (*http.Server, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"version": contract.Version,
		})
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
			return
		}
		writeJSON(w, http.StatusOK, deps.Stats())
	})

	mux.HandleFunc("/internal/verdict", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
			return
		}
		var v contract.VerdictUpdate
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&v); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
			return
		}
		if v.Verdict == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "verdict required"})
			return
		}
		deps.OnVerdict(v)
		writeJSON(w, http.StatusOK, contract.Ack{Accepted: true})
	})

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		log.Printf("[api] 管理 API 监听 %s", listen)
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[api] 服务退出: %v", err)
		}
	}()
	return srv, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
