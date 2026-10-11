// guardctl — proxy-guard Go 控制面 CLI。
//
// 子命令：
//
//	run      启动控制面（默认子命令）
//	check    校验配置后退出
//	version  打印版本
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/aiclient"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/bridge"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/contract"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/orchestrator"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/pgconfig"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/pool"
	"github.com/xwkpkp/proxy-guard/ctrl-go/internal/ruster"
)

const version = "0.1.0"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}

	switch cmd {
	case "run":
		if err := runCmd(args); err != nil {
			log.Fatalf("[guardctl] run: %v", err)
		}
	case "check":
		if err := checkCmd(args); err != nil {
			log.Fatalf("[guardctl] check: %v", err)
		}
	case "version":
		fmt.Printf("guardctl %s (contract %s)\n", version, contract.Version)
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 %q（可用: run / check / version）\n", cmd)
		os.Exit(2)
	}
}

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件路径")
	_ = fs.Parse(args)

	p, err := pgconfig.Load(*cfgPath)
	if err != nil {
		return err
	}
	log.Printf("[guardctl] 配置加载: %s（源 %d 个，池上限 %d，轮换 %s/%ds）",
		*cfgPath, len(p.Pool.Sources), p.Pool.MaxPoolSize, p.Rotator.Strategy, p.Rotator.SwitchInterval)
	if p.LLM.Enabled && !p.APIKeyPresent() {
		log.Printf("[guardctl] 提示: llm.enabled=true 但未配置 api_key，Python 端将空跑研判")
	}

	engine := pool.NewEngine(bridge.ToEngineConfig(p))
	rust := ruster.New(p.Ctrl.RustURL, p.Ctrl.CtrlToken)
	ai := aiclient.New(p.Ctrl.AIURL)

	orch := orchestrator.New(orchestrator.Options{
		Cfg:    p,
		Engine: engine,
		Rust:   rust,
		AI:     ai,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("[guardctl] 数据面 %s · AI %s · 管理 API %s", p.Ctrl.RustURL, p.Ctrl.AIURL, p.Ctrl.APIListen)
	return orch.Run(ctx)
}

func checkCmd(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath := fs.String("c", "config.yaml", "配置文件路径")
	_ = fs.Parse(args)

	p, err := pgconfig.Load(*cfgPath)
	if err != nil {
		return err
	}
	fmt.Printf("配置 OK: %s\n", *cfgPath)
	fmt.Printf("- 代理源          %d 个\n", len(p.Pool.Sources))
	fmt.Printf("- 轮换策略        %s（间隔 %ds / 失败切换 %d 次）\n", p.Rotator.Strategy, p.Rotator.SwitchInterval, p.Rotator.MaxFailures)
	fmt.Printf("- 路由模式        %s\n", p.Routing.Mode)
	fmt.Printf("- 数据面          %s\n", p.Ctrl.RustURL)
	fmt.Printf("- 管理 API        %s\n", p.Ctrl.APIListen)
	fmt.Printf("- AI 研判         %s（enabled=%t）\n", p.Ctrl.AIURL, p.LLM.Enabled)
	return nil
}
