# IP Gard

Linux 服务器 IP 访问日志监控工具。增量扫描 Apache/Nginx 访问日志，按 IP 聚合统计，提供 Web 界面查看、筛选、封禁，并可通过 iptables 自动拦截。

## 功能

- **日志扫描**：支持 Apache/Nginx combined/common 格式，增量读取（记录文件偏移与 inode）
- **IP 统计**：每个 IP 一行，记录总访问次数、10 分钟频率、最近链接、归属地等
- **Web 管理**：登录保护的管理界面，支持排序、筛选、分页、本地记住筛选偏好
- **IP 封禁**：数据库标记 + iptables `IPGARD` 链 DROP 规则（仅 Linux 生产环境）
- **归属地查询**：基于 [ip2region](https://github.com/lionsoul2014/ip2region) IPv4 库

## 环境要求

- **运行**：Linux（iptables 封禁功能）；Windows/macOS 可编译运行，但防火墙为 no-op
- **构建**：Go 1.26+
- **可选**：ip2region IPv4 数据库（`./data/ip2region_v4.xdb`）

## 快速开始

```bash
# 1. 复制配置
cp config.yaml.example config.yaml

# 2. 编译
go build -o ipgard .

# 3. 启动（默认 http://127.0.0.1:9300）
./ipgard
```

首次启动使用配置中的默认密码（`admin`），登录后可在设置页修改。

在 **设置** 页添加要监控的日志文件路径，保存后后台会按间隔自动扫描。

## 配置说明

配置文件为项目根目录下的 `config.yaml`（参考 `config.yaml.example`）：

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `server.port` | HTTP 端口 | `9300` |
| `server.base_path` | 反向代理子路径，如 `/ipgard` | 空 |
| `auth.password` | 首次启动写入数据库的密码 | `admin` |
| `database.path` | SQLite 数据库路径 | `./data/ipgard.db` |
| `scanner.interval_seconds` | 日志扫描间隔（秒） | `10` |
| `firewall.enabled` | 是否启用 iptables 封禁 | `true` |
| `firewall.chain` | iptables 自定义链名 | `IPGARD` |
| `geoip.enabled` | 是否启用归属地查询 | `true` |
| `geoip.db_path` | ip2region IPv4 库路径 | `./data/ip2region_v4.xdb` |

## 归属地库

从 [ip2region](https://github.com/lionsoul2014/ip2region) 下载 `ip2region_v4.xdb`，放到 `./data/` 目录。日志中若无 IPv6，无需配置 v6 库。

## iptables 说明

启用防火墙后，程序会维护名为 `IPGARD`（可配置）的自定义链，对封禁 IP 写入 DROP 规则。需要 root 权限或相应的 `CAP_NET_ADMIN` 能力。

Web 界面中可单独管理 iptables 规则（添加/移除），与数据库中的封禁状态会尽量保持同步。

## 项目结构

```
ipgard/
├── main.go                 # 入口
├── config/                 # 配置加载
├── html/                   # 前端页面（Pico CSS + 原生 JS）
├── internal/
│   ├── auth/               # 密码与会话
│   ├── db/                 # SQLite 存储
│   ├── firewall/           # iptables 封装
│   ├── geoip/              # ip2region 查询
│   ├── handler/            # HTTP API
│   ├── logdiscover/        # 日志文件发现
│   ├── parser/             # 访问日志解析
│   ├── scanner/            # 增量扫描
│   └── server/             # Gin HTTP 服务
├── config.yaml.example
└── testdata/logs/          # 本地测试日志（已 gitignore）
```

## 开发

```bash
# 运行测试
go test ./...

# 本地测试日志
# 大体积日志放在 testdata/logs/，不会提交到仓库
```

## 许可证

未指定。使用前请自行确认依赖库的许可证。
