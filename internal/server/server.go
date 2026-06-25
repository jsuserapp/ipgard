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
	"ipgard/internal/handler"
	"ipgard/internal/scanner"
)

type Server struct {
	cfg     *config.Config
	httpSrv *http.Server
}

func New(cfg *config.Config, store *db.Store, authMgr *auth.Manager) *Server {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery(), gin.Logger())

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

	root := engine.Group(basePath)
	h := handler.New(cfg, store, authMgr)
	h.Register(root)

	root.Static("/static", "./html/static")
	root.GET("/", func(c *gin.Context) { c.File("./html/index.html") })
	root.GET("/login", func(c *gin.Context) { c.File("./html/login.html") })
	root.GET("/settings", func(c *gin.Context) { c.File("./html/settings.html") })

	return &Server{
		cfg: cfg,
		httpSrv: &http.Server{
			Addr:    cfg.ListenAddr(),
			Handler: engine,
		},
	}
}

func (s *Server) Start(ctx context.Context, store *db.Store) error {
	scan := scanner.New(store, time.Duration(s.cfg.Scanner.IntervalSeconds)*time.Second)
	go scan.Run(ctx)

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
