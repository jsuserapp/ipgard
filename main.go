package main

import (
	"context"
	"fmt"

	"github.com/jsuserapp/jufmt"
	"github.com/jsuserapp/service"
	"ipgard/config"
	"ipgard/internal/auth"
	"ipgard/internal/db"
	"ipgard/internal/firewall"
	"ipgard/internal/geoip"
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

		fw := firewall.New(cfg.Firewall.Enabled, cfg.Firewall.Chain, cfg.Firewall.IptablesPath, cfg.Firewall.CIDRIpSet, cfg.Firewall.IpSetPath)
		geo := geoip.NewOptional(cfg.GeoIP.Enabled, cfg.GeoIP.DBPath)
		if geo.Available() {
			if idx, err := store.IPLocationIndex(); err == nil && len(idx) > 0 {
				geo.Warm(idx)
				jufmt.Green.Println(fmt.Sprintf("IP 归属地库已加载 (IPv4)，预热缓存 %d 条", len(idx)))
			} else {
				jufmt.Green.Println("IP 归属地库已加载 (IPv4):", geoip.ResolveDBPath(cfg.GeoIP.DBPath))
			}
		} else if cfg.GeoIP.Enabled {
			jufmt.Red.Println("IP 归属地库未就绪，请放置 IPv4 库:", geoip.DefaultV4DB)
		}
		defer geo.Close()

		srv := server.New(cfg, store, authMgr, fw, geo)

		addr := cfg.ListenAddr()
		if bp := cfg.NormalizedBasePath(); bp != "" {
			jufmt.Green.Println(fmt.Sprintf("IP Gard 监听 http://127.0.0.1%s%s", addr, bp))
		} else {
			jufmt.Green.Println(fmt.Sprintf("IP Gard 监听 http://127.0.0.1%s", addr))
		}
		if fw.Available() {
			jufmt.Green.Println("iptables 防火墙已启用，链:", cfg.Firewall.Chain)
			if fw.CIDRSupported() {
				jufmt.Green.Println("网段封禁 ipset:", cfg.Firewall.CIDRIpSet)
			}
		}

		if err := srv.Start(ctx, store); err != nil {
			jufmt.Red.Println("服务异常:", err.Error())
		}
	})
	if err != nil {
		jufmt.Red.Println("启动服务失败:", err.Error())
	}
}
