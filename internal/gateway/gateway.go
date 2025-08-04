/*
   Project: RainbowBridge
   Github: https://github.com/landers1037
   Copyright Renj
*/

package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"rainbowbridge/internal/configer"
	"rainbowbridge/internal/logger"
	"rainbowbridge/internal/middleware"
	"rainbowbridge/internal/proxy"
	"rainbowbridge/internal/server"
	"rainbowbridge/pkg/errors"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/http2"
)

// RouteRule 路由规则
type RouteRule struct {
	// Name 规则名称
	Name string `json:"name"`
	// Pattern 匹配模式
	Pattern string `json:"pattern"`
	// Type 规则类型 (host/path/header)
	Type string `json:"type"`
	// Regex 编译后的正则表达式指针，用于高效的模式匹配
	Regex *regexp.Regexp `json:"-"`
	// ServiceName 服务名称
	ServiceName string `json:"service_name"`
	// Priority 优先级
	Priority int `json:"priority"`
}

// Service 服务定义
type Service struct {
	// Name 服务名称
	Name string `json:"name"`
	// Proxy 代理实例指针，用于处理请求转发
	Proxy proxy.Proxy `json:"-"`
	// Middlewares 中间件列表
	Middlewares []string `json:"middlewares"`
	// TLS 是否启用TLS
	TLS bool `json:"tls"`
	// Domains 绑定的域名列表
	Domains []string `json:"domains"`
}

// Gateway 网关
type Gateway struct {
	// config 配置管理器指针，用于获取网关配置信息
	config *configer.Manager
	// httpServer HTTP服务器指针，用于处理HTTP请求
	httpServer *server.HTTPServer
	// httpsServer HTTPS服务器指针，用于处理HTTPS请求
	httpsServer *server.HTTPServer
	// services 服务映射，键为服务名，值为服务实例指针
	services map[string]*Service
	// routes 路由规则列表，用于存储所有路由规则
	routes []*RouteRule
	// middlewares 中间件映射，键为中间件名，值为中间件处理函数
	middlewares map[string]gin.HandlerFunc
	// tlsConfig TLS配置指针，用于HTTPS服务器的TLS配置
	tlsConfig *tls.Config
	// running 运行状态，用于标识网关是否正在运行
	running bool
	// mutex 读写锁，用于保护网关状态的并发访问
	mutex sync.RWMutex
}

// NewGateway 创建网关
func NewGateway(configManager *configer.Manager) (*Gateway, error) {
	if configManager == nil {
		return nil, errors.ErrGatewayConfigInvalid
	}

	gateway := &Gateway{
		config:      configManager,
		services:    make(map[string]*Service),
		routes:      make([]*RouteRule, 0),
		middlewares: make(map[string]gin.HandlerFunc),
	}

	// 初始化中间件
	if err := gateway.initMiddlewares(); err != nil {
		return nil, fmt.Errorf("init middlewares failed: %v", err)
	}

	// 初始化服务
	if err := gateway.initServices(); err != nil {
		return nil, fmt.Errorf("init services failed: %v", err)
	}

	// 初始化路由
	if err := gateway.initRoutes(); err != nil {
		return nil, fmt.Errorf("init routes failed: %v", err)
	}

	// 初始化TLS配置
	if err := gateway.initTLSConfig(); err != nil {
		return nil, fmt.Errorf("init TLS config failed: %v", err)
	}

	// 初始化服务器
	if err := gateway.initServers(); err != nil {
		return nil, fmt.Errorf("init servers failed: %v", err)
	}

	// 注册配置重载回调
	configManager.AddReloadCallback(gateway.onConfigReload)

	return gateway, nil
}

// initMiddlewares 初始化中间件
func (g *Gateway) initMiddlewares() error {
	config := g.config.GetConfig()

	// CORS中间件
	corsConfig := &middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}
	g.middlewares["cors"] = middleware.CORS(corsConfig)

	// 限流中间件
	rateLimitConfig := &middleware.RateLimitConfig{
		Rate:  100.0, // 每秒100个请求
		Burst: 200,   // 突发200个请求
	}
	g.middlewares["rateLimit"] = middleware.RateLimit(rateLimitConfig)

	// 熔断器中间件
	circuitBreakerConfig := &middleware.CircuitBreakerConfig{
		MaxRequests: 10,
		Interval:    30 * time.Second,
		Timeout:     60 * time.Second,
	}
	g.middlewares["circuitBreaker"] = middleware.CircuitBreakerMiddleware(circuitBreakerConfig)

	// 重试中间件
	retryConfig := &middleware.RetryConfig{
		MaxRetries: 3,
		RetryDelay: 100 * time.Millisecond,
	}
	g.middlewares["retry"] = middleware.Retry(retryConfig)

	// 压缩中间件
	if config.HTTP != nil && config.HTTP.Middlewares != nil {
		if compressConfig, exists := config.HTTP.Middlewares["compress"]; exists && compressConfig.Compress != nil {
			g.middlewares["compress"] = middleware.Compress(compressConfig.Compress)
		}
	}

	// 请求体大小限制中间件
	g.middlewares["limit"] = middleware.RequestBodyLimit(10 * 1024 * 1024) // 10MB

	// 自定义头部中间件
	customHeaders := map[string]string{
		"X-Gateway-Name": "RainbowBridge",
		"Server":         "",
	}
	g.middlewares["customHeader"] = middleware.CustomHeaders(customHeaders)

	// 错误处理中间件
	g.middlewares["error"] = middleware.ErrorHandler()

	// 请求追踪中间件
	g.middlewares["trace"] = middleware.RequestTrace()

	// 重定向HTTPS中间件
	g.middlewares["redirect-to-https"] = func(c *gin.Context) {
		if c.Request.TLS == nil {
			httpsURL := "https://" + c.Request.Host + c.Request.RequestURI
			c.Redirect(http.StatusMovedPermanently, httpsURL)
			c.Abort()
			return
		}
		c.Next()
	}

	return nil
}

// initServices 初始化服务
func (g *Gateway) initServices() error {
	config := g.config.GetConfig()

	if config.HTTP == nil || config.HTTP.Services == nil {
		return nil
	}

	for serviceName, serviceConfig := range config.HTTP.Services {
		if serviceConfig.LoadBalancer == nil || len(serviceConfig.LoadBalancer.Servers) == 0 {
			continue
		}

		// 创建代理目标
		targets := make([]*proxy.Target, 0, len(serviceConfig.LoadBalancer.Servers))
		for _, serverConfig := range serviceConfig.LoadBalancer.Servers {
			targets = append(targets, &proxy.Target{
				URL:     serverConfig.URL,
				Weight:  1,
				Healthy: true,
			})
		}

		// 创建代理配置
		proxyConfig := &proxy.Config{
			Name:                serviceName,
			Type:                proxy.PROXY_TYPE_HTTP,
			Targets:             targets,
			LoadBalanceStrategy: proxy.STRATEGY_ROUND_ROBIN,
			HealthCheck: &proxy.HealthCheckConfig{
				Enabled:        true,
				Interval:       30 * time.Second,
				Timeout:        5 * time.Second,
				Path:           "/health",
				ExpectedStatus: http.StatusOK,
			},
		}

		// 创建代理
		proxyInstance, err := proxy.NewProxy(proxyConfig)
		if err != nil {
			return fmt.Errorf("create proxy for service %s failed: %v", serviceName, err)
		}

		// 创建服务
		service := &Service{
			Name:        serviceName,
			Proxy:       proxyInstance,
			Middlewares: []string{"trace", "cors", "rateLimit", "customHeader"},
			TLS:         false,
			Domains:     []string{},
		}

		g.services[serviceName] = service

		// 启动代理
		if err := proxyInstance.Start(); err != nil {
			logger.Errorf("Start proxy for service %s failed: %v", serviceName, err)
		}
	}

	return nil
}

// initRoutes 初始化路由
func (g *Gateway) initRoutes() error {
	config := g.config.GetConfig()

	if config.HTTP == nil || config.HTTP.Routers == nil {
		return nil
	}

	for routeName, routerConfig := range config.HTTP.Routers {
		// 解析路由规则
		rule, err := g.parseRouteRule(routeName, routerConfig.Rule)
		if err != nil {
			logger.Errorf("Parse route rule %s failed: %v", routeName, err)
			continue
		}

		rule.ServiceName = routerConfig.Service
		rule.Priority = 100 // 默认优先级

		g.routes = append(g.routes, rule)
	}

	return nil
}

// parseRouteRule 解析路由规则
func (g *Gateway) parseRouteRule(name, ruleStr string) (*RouteRule, error) {
	rule := &RouteRule{
		Name: name,
	}

	// 解析规则类型和模式
	if strings.HasPrefix(ruleStr, "Host(") {
		rule.Type = "host"
		// 提取Host规则中的域名
		start := strings.Index(ruleStr, "`")
		end := strings.LastIndex(ruleStr, "`")
		if start != -1 && end != -1 && start < end {
			rule.Pattern = ruleStr[start+1 : end]
		}
	} else if strings.HasPrefix(ruleStr, "HostRegexp(") {
		rule.Type = "host_regexp"
		// 提取HostRegexp规则中的正则表达式
		start := strings.Index(ruleStr, "`")
		end := strings.LastIndex(ruleStr, "`")
		if start != -1 && end != -1 && start < end {
			rule.Pattern = ruleStr[start+1 : end]
		}
	} else if strings.HasPrefix(ruleStr, "PathPrefix(") {
		rule.Type = "path_prefix"
		// 提取PathPrefix规则中的路径前缀
		start := strings.Index(ruleStr, "`")
		end := strings.LastIndex(ruleStr, "`")
		if start != -1 && end != -1 && start < end {
			rule.Pattern = ruleStr[start+1 : end]
		}
	} else {
		return nil, fmt.Errorf("unsupported rule type: %s", ruleStr)
	}

	// 编译正则表达式
	if rule.Type == "host_regexp" {
		regex, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile regex %s failed: %v", rule.Pattern, err)
		}
		rule.Regex = regex
	}

	return rule, nil
}

// initTLSConfig 初始化TLS配置
func (g *Gateway) initTLSConfig() error {
	config := g.config.GetConfig()

	if config.TLS == nil || config.TLS.Certificates == nil {
		return nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// 加载证书
	for certName, certConfig := range config.TLS.Certificates {
		cert, err := tls.LoadX509KeyPair(certConfig.CertFile, certConfig.KeyFile)
		if err != nil {
			logger.Errorf("Load certificate %s failed: %v", certName, err)
			continue
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	// 设置SNI回调
	tlsConfig.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		for i, cert := range tlsConfig.Certificates {
			if len(cert.Certificate) > 0 {
				return &tlsConfig.Certificates[i], nil
			}
		}
		return nil, fmt.Errorf("no certificate found")
	}

	g.tlsConfig = tlsConfig
	return nil
}

// initServers 初始化服务器
func (g *Gateway) initServers() error {
	config := g.config.GetConfig()

	if config.EntryPoints == nil {
		return errors.ErrGatewayConfigInvalid
	}

	// 创建HTTP服务器
	if httpEntry, exists := config.EntryPoints["http"]; exists {
		engine := g.createGinEngine(false)
		httpConfig := &server.Config{
			Name:     "http",
			Protocol: server.PROTOCOL_HTTP,
			Address:  "0.0.0.0",
			Port:     80,
		}

		// 解析地址和端口
		if httpEntry.Address != "" {
			parts := strings.Split(httpEntry.Address, ":")
			if len(parts) == 2 {
				httpConfig.Address = "0.0.0.0"
				if port := parts[1]; port != "" {
					if p, err := parsePort(port); err == nil {
						httpConfig.Port = p
					}
				}
			}
		}

		httpServer, err := server.NewHTTPServer(httpConfig, engine)
		if err != nil {
			return fmt.Errorf("create HTTP server failed: %v", err)
		}
		g.httpServer = httpServer
	}

	// 创建HTTPS服务器
	if httpsEntry, exists := config.EntryPoints["https"]; exists && g.tlsConfig != nil {
		engine := g.createGinEngine(true)
		httpsConfig := &server.Config{
			Name:     "https",
			Protocol: server.PROTOCOL_HTTPS,
			Address:  "0.0.0.0",
			Port:     443,
			TLSConfig: &server.TLSConfig{
				InsecureSkipVerify: config.InsecureSkipVerify,
				MinVersion:         tls.VersionTLS12,
			},
			EnableHTTP2: true,
		}

		// 解析地址和端口
		if httpsEntry.Address != "" {
			parts := strings.Split(httpsEntry.Address, ":")
			if len(parts) == 2 {
				httpsConfig.Address = "0.0.0.0"
				if port := parts[1]; port != "" {
					if p, err := parsePort(port); err == nil {
						httpsConfig.Port = p
					}
				}
			}
		}

		httpsServer, err := server.NewHTTPServer(httpsConfig, engine)
		if err != nil {
			return fmt.Errorf("create HTTPS server failed: %v", err)
		}

		// 配置HTTP2
		if httpsConfig.EnableHTTP2 {
			http2.ConfigureServer(httpsServer.GetServer(), &http2.Server{})
		}

		g.httpsServer = httpsServer
	}

	return nil
}

// createGinEngine 创建Gin引擎
func (g *Gateway) createGinEngine(isHTTPS bool) *gin.Engine {
	engine := gin.New()

	// 添加全局中间件
	engine.Use(g.middlewares["trace"])
	engine.Use(gin.Recovery())

	// 添加路由处理
	engine.NoRoute(g.handleRequest)

	return engine
}

// handleRequest 处理请求
func (g *Gateway) handleRequest(c *gin.Context) {
	// 匹配路由规则
	service := g.matchRoute(c)
	if service == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Service not found",
			"code":  http.StatusNotFound,
		})
		return
	}

	// 应用中间件
	for _, middlewareName := range service.Middlewares {
		if middleware, exists := g.middlewares[middlewareName]; exists {
			middleware(c)
			if c.IsAborted() {
				return
			}
		}
	}

	// 转发请求到后端服务
	if httpProxy, ok := service.Proxy.(*proxy.HTTPProxy); ok {
		handler := httpProxy.CreateGinHandler()
		handler(c)
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Invalid proxy type",
			"code":  http.StatusInternalServerError,
		})
	}
}

// matchRoute 匹配路由规则
func (g *Gateway) matchRoute(c *gin.Context) *Service {
	host := c.Request.Host
	path := c.Request.URL.Path

	// 移除端口号
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	for _, route := range g.routes {
		matched := false

		switch route.Type {
		case "host":
			matched = host == route.Pattern
		case "host_regexp":
			if route.Regex != nil {
				matched = route.Regex.MatchString(host)
			}
		case "path_prefix":
			matched = strings.HasPrefix(path, route.Pattern)
		}

		if matched {
			if service, exists := g.services[route.ServiceName]; exists {
				return service
			}
		}
	}

	return nil
}

// parsePort 解析端口号
func parsePort(portStr string) (int, error) {
	var port int
	_, err := fmt.Sscanf(portStr, "%d", &port)
	return port, err
}

// Start 启动网关
func (g *Gateway) Start() error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if g.running {
		return fmt.Errorf("%w: gateway already running", errors.ErrGatewayStartFailed)
	}

	logger.Info("Starting RainbowBridge Gateway")

	// 启动HTTP服务器
	if g.httpServer != nil {
		if err := g.httpServer.Start(); err != nil {
			return fmt.Errorf("%w: start HTTP server failed: %v", errors.ErrGatewayStartFailed, err)
		}
		logger.Info("HTTP server started on port 80")
	}

	// 启动HTTPS服务器
	if g.httpsServer != nil {
		if err := g.httpsServer.Start(); err != nil {
			return fmt.Errorf("%w: start HTTPS server failed: %v", errors.ErrGatewayStartFailed, err)
		}
		logger.Info("HTTPS server started on port 443")
	}

	g.running = true
	logger.Infof("Gateway started with %d services and %d routes", len(g.services), len(g.routes))

	return nil
}

// Stop 停止网关
func (g *Gateway) Stop(ctx context.Context) error {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	if !g.running {
		return nil
	}

	logger.Info("Stopping RainbowBridge Gateway")

	// 停止HTTP服务器
	if g.httpServer != nil {
		if err := g.httpServer.Stop(ctx); err != nil {
			logger.Errorf("Stop HTTP server failed: %v", err)
		}
	}

	// 停止HTTPS服务器
	if g.httpsServer != nil {
		if err := g.httpsServer.Stop(ctx); err != nil {
			logger.Errorf("Stop HTTPS server failed: %v", err)
		}
	}

	// 停止所有代理
	for _, service := range g.services {
		if err := service.Proxy.Stop(); err != nil {
			logger.Errorf("Stop proxy %s failed: %v", service.Name, err)
		}
	}

	g.running = false
	logger.Info("Gateway stopped")

	return nil
}

// IsRunning 检查网关是否运行中
func (g *Gateway) IsRunning() bool {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.running
}

// GetServices 获取服务列表
func (g *Gateway) GetServices() map[string]*Service {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.services
}

// GetRoutes 获取路由列表
func (g *Gateway) GetRoutes() []*RouteRule {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.routes
}

// onConfigReload 配置重载回调
func (g *Gateway) onConfigReload(config *configer.Config) {
	logger.Info("Gateway config reloaded, reinitializing...")

	// 重新初始化服务
	if err := g.initServices(); err != nil {
		logger.Errorf("Reinit services failed: %v", err)
	}

	// 重新初始化路由
	if err := g.initRoutes(); err != nil {
		logger.Errorf("Reinit routes failed: %v", err)
	}
}
