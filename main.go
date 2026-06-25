package main

import (
	"context"
	"fmt"

	"github.com/jsuserapp/jufmt"
	"github.com/jsuserapp/service"
	"ipgard/config"
	"ipgard/internal/auth"
	"ipgard/internal/db"
	"ipgard/internal/server"
)

func main() {
	err := service.StartService("ipgard", "IP access log monitor", func(ctx context.Context) {
		cfg, err := config.Load(config.DefaultConfigFile)
		if err != nil {
			jufmt.Red.Println("加载配置失败:", err.Error())
			return
		}

		store, err := db.Open(cfg.Database.Path)
		if err != nil {
			jufmt.Red.Println("打开数据库失败:", err.Error())
			return
		}
		defer store.Close()

		authMgr := auth.New(store)
		if err := authMgr.EnsurePassword(cfg.Auth.Password); err != nil {
			jufmt.Red.Println("初始化密码失败:", err.Error())
			return
		}

		srv := server.New(cfg, store, authMgr)
		addr := cfg.ListenAddr()
		if bp := cfg.NormalizedBasePath(); bp != "" {
			jufmt.Green.Println(fmt.Sprintf("IP Gard 监听 http://127.0.0.1%s%s", addr, bp))
		} else {
			jufmt.Green.Println(fmt.Sprintf("IP Gard 监听 http://127.0.0.1%s", addr))
		}

		if err := srv.Start(ctx, store); err != nil {
			jufmt.Red.Println("服务异常:", err.Error())
		}
	})
	if err != nil {
		jufmt.Red.Println("启动服务失败:", err.Error())
	}
}
