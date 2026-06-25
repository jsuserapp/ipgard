package server

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"ipgard/config"
	"ipgard/internal/auth"
	"ipgard/internal/db"
	"ipgard/internal/firewall"
	"ipgard/internal/geoip"
	"ipgard/internal/handler"
	"ipgard/internal/scanner"
)

type Server struct {
	cfg     *config.Config
	httpSrv *http.Server
	fw      firewall.Manager
	geo     geoip.Resolver
	scan    *scanner.Scanner
}

func New(cfg *config.Config, store *db.Store, authMgr *auth.Manager, fw firewall.Manager, geo geoip.Resolver) *Server {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())

	basePath := cfg.NormalizedBasePath()
	cookiePath := basePath
	if cookiePath == "" {
		cookiePath = "/"
	}

	storeSession := cookie.NewStore([]byte("ipgard-session-secret-change-me"))
	storeSession.Options(sessions.Options{
		Path:     cookiePath,
		MaxAge:   86400 * 7,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	engine.Use(sessions.Sessions("ipgard", storeSession))

	scan := scanner.New(store, geo, time.Duration(cfg.Scanner.IntervalSeconds)*time.Second)

	root := engine.Group(basePath)
	h := handler.New(cfg, store, authMgr, fw, geo, scan)
	h.Register(root)

	root.Static("/static", "./html/static")
	root.GET("/", func(c *gin.Context) { c.File("./html/index.html") })
	root.GET("/login", func(c *gin.Context) { c.File("./html/login.html") })
	root.GET("/settings", func(c *gin.Context) { c.File("./html/settings.html") })

	return &Server{
		cfg:  cfg,
		fw:   fw,
		geo:  geo,
		scan: scan,
		httpSrv: &http.Server{
			Addr:    cfg.ListenAddr(),
			Handler: engine,
		},
	}
}

func (s *Server) Start(ctx context.Context, store *db.Store) error {
	if err := s.fw.Init(); err != nil {
		return fmt.Errorf("firewall init: %w", err)
	}
	blocked, err := store.ListBlockedIPs()
	if err != nil {
		return fmt.Errorf("load blocked ips: %w", err)
	}
	if err := s.fw.Sync(blocked); err != nil {
		return fmt.Errorf("firewall sync: %w", err)
	}

	go s.scan.Run(ctx)

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpSrv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	}
}
