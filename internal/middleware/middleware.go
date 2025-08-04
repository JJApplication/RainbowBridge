/*
   Project: RainbowBridge
   Github: https://github.com/landers1037
   Copyright Renj
*/

package middleware

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"rainbowbridge/internal/configer"
	"rainbowbridge/internal/logger"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// CORSConfig CORS配置
type CORSConfig struct {
	// AllowOrigins 允许的源
	AllowOrigins []string `json:"allow_origins"`
	// AllowMethods 允许的方法
	AllowMethods []string `json:"allow_methods"`
	// AllowHeaders 允许的头部
	AllowHeaders []string `json:"allow_headers"`
	// ExposeHeaders 暴露的头部
	ExposeHeaders []string `json:"expose_headers"`
	// AllowCredentials 是否允许凭证
	AllowCredentials bool `json:"allow_credentials"`
	// MaxAge 预检请求缓存时间
	MaxAge time.Duration `json:"max_age"`
}

// RateLimitConfig 限流配置
type RateLimitConfig struct {
	// Rate 每秒请求数
	Rate float64 `json:"rate"`
	// Burst 突发请求数
	Burst int `json:"burst"`
	// KeyFunc 获取限流键的函数
	KeyFunc func(*gin.Context) string `json:"-"`
}

// CircuitBreakerConfig 熔断器配置
type CircuitBreakerConfig struct {
	// MaxRequests 半开状态下的最大请求数
	MaxRequests uint32 `json:"max_requests"`
	// Interval 统计间隔
	Interval time.Duration `json:"interval"`
	// Timeout 熔断超时时间
	Timeout time.Duration `json:"timeout"`
	// ReadyToTrip 判断是否应该熔断的函数
	ReadyToTrip func(counts Counts) bool `json:"-"`
}

// RetryConfig 重试配置
type RetryConfig struct {
	// MaxRetries 最大重试次数
	MaxRetries int `json:"max_retries"`
	// RetryDelay 重试延迟
	RetryDelay time.Duration `json:"retry_delay"`
	// RetryCondition 重试条件函数
	RetryCondition func(*gin.Context, error) bool `json:"-"`
}

// Counts 熔断器计数
type Counts struct {
	// Requests 请求总数
	Requests uint32
	// TotalSuccesses 成功总数
	TotalSuccesses uint32
	// TotalFailures 失败总数
	TotalFailures uint32
	// ConsecutiveSuccesses 连续成功数
	ConsecutiveSuccesses uint32
	// ConsecutiveFailures 连续失败数
	ConsecutiveFailures uint32
}

// State 熔断器状态
type State int

const (
	// STATE_CLOSED 关闭状态
	STATE_CLOSED State = iota
	// STATE_HALF_OPEN 半开状态
	STATE_HALF_OPEN
	// STATE_OPEN 开启状态
	STATE_OPEN
)

// CircuitBreaker 熔断器
type CircuitBreaker struct {
	// config 熔断器配置指针，用于存储熔断器配置信息
	config *CircuitBreakerConfig
	// state 熔断器状态，用于记录当前熔断器的状态
	state State
	// counts 计数器，用于统计请求成功失败次数
	counts Counts
	// expiry 过期时间，用于记录熔断器状态过期时间
	expiry time.Time
	// mutex 互斥锁，用于保护熔断器状态的并发访问
	mutex sync.Mutex
}

// RateLimiter 限流器
type RateLimiter struct {
	// limiters 限流器映射，键为限流键，值为限流器指针
	limiters map[string]*rate.Limiter
	// config 限流配置指针，用于存储限流配置信息
	config *RateLimitConfig
	// mutex 读写锁，用于保护限流器映射的并发访问
	mutex sync.RWMutex
}

// NewRateLimiter 创建限流器
func NewRateLimiter(config *RateLimitConfig) *RateLimiter {
	if config.KeyFunc == nil {
		config.KeyFunc = func(c *gin.Context) string {
			return c.ClientIP()
		}
	}

	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}
}

// Allow 检查是否允许请求
func (rl *RateLimiter) Allow(key string) bool {
	rl.mutex.RLock()
	limiter, exists := rl.limiters[key]
	rl.mutex.RUnlock()

	if !exists {
		rl.mutex.Lock()
		limiter, exists = rl.limiters[key]
		if !exists {
			limiter = rate.NewLimiter(rate.Limit(rl.config.Rate), rl.config.Burst)
			rl.limiters[key] = limiter
		}
		rl.mutex.Unlock()
	}

	return limiter.Allow()
}

// NewCircuitBreaker 创建熔断器
func NewCircuitBreaker(config *CircuitBreakerConfig) *CircuitBreaker {
	if config.ReadyToTrip == nil {
		config.ReadyToTrip = func(counts Counts) bool {
			return counts.ConsecutiveFailures > 5
		}
	}

	return &CircuitBreaker{
		config: config,
		state:  STATE_CLOSED,
	}
}

// Execute 执行请求
func (cb *CircuitBreaker) Execute(req func() error) error {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()

	now := time.Now()
	state, generation := cb.currentState(now)

	if state == STATE_OPEN {
		return fmt.Errorf("circuit breaker is open")
	}

	err := req()
	cb.onRequest(now, generation, err == nil)

	return err
}

// currentState 获取当前状态
func (cb *CircuitBreaker) currentState(now time.Time) (State, uint64) {
	switch cb.state {
	case STATE_CLOSED:
		if cb.config.ReadyToTrip(cb.counts) {
			cb.setState(STATE_OPEN, now)
			return STATE_OPEN, 0
		}
	case STATE_OPEN:
		if cb.expiry.Before(now) {
			cb.setState(STATE_HALF_OPEN, now)
			return STATE_HALF_OPEN, 0
		}
	case STATE_HALF_OPEN:
		if cb.counts.Requests >= cb.config.MaxRequests {
			if cb.counts.TotalFailures == 0 {
				cb.setState(STATE_CLOSED, now)
				return STATE_CLOSED, 0
			} else {
				cb.setState(STATE_OPEN, now)
				return STATE_OPEN, 0
			}
		}
	}

	return cb.state, 0
}

// setState 设置状态
func (cb *CircuitBreaker) setState(state State, now time.Time) {
	cb.state = state
	cb.counts = Counts{}

	if state == STATE_OPEN {
		cb.expiry = now.Add(cb.config.Timeout)
	}
}

// onRequest 请求回调
func (cb *CircuitBreaker) onRequest(now time.Time, generation uint64, success bool) {
	cb.counts.Requests++

	if success {
		cb.counts.TotalSuccesses++
		cb.counts.ConsecutiveSuccesses++
		cb.counts.ConsecutiveFailures = 0
	} else {
		cb.counts.TotalFailures++
		cb.counts.ConsecutiveFailures++
		cb.counts.ConsecutiveSuccesses = 0
	}
}

// CORS 中间件
func CORS(config *CORSConfig) gin.HandlerFunc {
	if config == nil {
		config = &CORSConfig{
			AllowOrigins:     []string{"*"},
			AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
			AllowCredentials: false,
			MaxAge:           12 * time.Hour,
		}
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// 设置CORS头部
		if len(config.AllowOrigins) > 0 {
			if config.AllowOrigins[0] == "*" {
				c.Header("Access-Control-Allow-Origin", "*")
			} else {
				for _, allowOrigin := range config.AllowOrigins {
					if origin == allowOrigin {
						c.Header("Access-Control-Allow-Origin", origin)
						break
					}
				}
			}
		}

		if len(config.AllowMethods) > 0 {
			c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowMethods, ", "))
		}

		if len(config.AllowHeaders) > 0 {
			c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowHeaders, ", "))
		}

		if len(config.ExposeHeaders) > 0 {
			c.Header("Access-Control-Expose-Headers", strings.Join(config.ExposeHeaders, ", "))
		}

		if config.AllowCredentials {
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		if config.MaxAge > 0 {
			c.Header("Access-Control-Max-Age", strconv.Itoa(int(config.MaxAge.Seconds())))
		}

		// 处理预检请求
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// RateLimit 限流中间件
func RateLimit(config *RateLimitConfig) gin.HandlerFunc {
	limiter := NewRateLimiter(config)

	return func(c *gin.Context) {
		key := config.KeyFunc(c)
		if !limiter.Allow(key) {
			logger.Warnf("Rate limit exceeded for key: %s", key)
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded",
				"code":  http.StatusTooManyRequests,
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// CircuitBreakerMiddleware 熔断器中间件
func CircuitBreakerMiddleware(config *CircuitBreakerConfig) gin.HandlerFunc {
	cb := NewCircuitBreaker(config)

	return func(c *gin.Context) {
		err := cb.Execute(func() error {
			c.Next()
			if c.Writer.Status() >= 500 {
				return fmt.Errorf("server error: %d", c.Writer.Status())
			}
			return nil
		})

		if err != nil {
			logger.Errorf("Circuit breaker error: %v", err)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Service temporarily unavailable",
				"code":  http.StatusServiceUnavailable,
			})
			c.Abort()
		}
	}
}

// Retry 重试中间件
func Retry(config *RetryConfig) gin.HandlerFunc {
	if config.RetryCondition == nil {
		config.RetryCondition = func(c *gin.Context, err error) bool {
			return c.Writer.Status() >= 500
		}
	}

	return func(c *gin.Context) {
		for i := 0; i <= config.MaxRetries; i++ {
			// 创建一个新的context副本用于重试
			if i > 0 {
				logger.Infof("Retrying request, attempt %d/%d", i, config.MaxRetries)
				time.Sleep(config.RetryDelay)
			}

			// 执行请求
			c.Next()

			// 检查是否需要重试
			if i < config.MaxRetries && config.RetryCondition(c, nil) {
				logger.Warnf("Retrying request, attempt %d/%d", i+1, config.MaxRetries)
				time.Sleep(config.RetryDelay)
				// 重置响应状态，准备重试
				c.Writer.Header().Del("Content-Length")
				c.Writer.Header().Del("Content-Type")
				continue
			}
			break
		}
	}
}

// Compress 压缩中间件
func Compress(config *configer.CompressConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 检查客户端是否支持gzip
		if !strings.Contains(c.Request.Header.Get("Accept-Encoding"), "gzip") {
			c.Next()
			return
		}

		// 检查内容类型是否需要排除
		contentType := c.Writer.Header().Get("Content-Type")
		for _, excludedType := range config.ExcludedContentTypes {
			if strings.Contains(contentType, excludedType) {
				c.Next()
				return
			}
		}

		// 设置压缩头部
		c.Header("Content-Encoding", config.DefaultEncoding)
		c.Header("Vary", "Accept-Encoding")

		// 创建gzip写入器
		gzipWriter := gzip.NewWriter(c.Writer)
		defer func() {
			if err := gzipWriter.Close(); err != nil {
				logger.Errorf("Failed to close gzip writer: %v", err)
			}
		}()

		// 替换响应写入器
		c.Writer = &gzipResponseWriter{
			ResponseWriter: c.Writer,
			writer:         gzipWriter,
			minSize:        config.MinResponseBodyBytes,
		}

		c.Next()
	}
}

// gzipResponseWriter gzip响应写入器
type gzipResponseWriter struct {
	gin.ResponseWriter
	// writer gzip写入器指针，用于压缩响应内容
	writer io.Writer
	// minSize 最小压缩大小，小于此大小的响应不进行压缩
	minSize int64
	// written 已写入字节数
	written int64
}

// Write 写入数据
func (g *gzipResponseWriter) Write(data []byte) (int, error) {
	g.written += int64(len(data))
	if g.written >= g.minSize {
		return g.writer.Write(data)
	}
	return g.ResponseWriter.Write(data)
}

// RequestBodyLimit 请求体大小限制中间件
func RequestBodyLimit(maxSize int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxSize {
			logger.Warnf("Request body too large: %d bytes, max: %d bytes", c.Request.ContentLength, maxSize)
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Request body too large",
				"code":  http.StatusRequestEntityTooLarge,
			})
			c.Abort()
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSize)
		c.Next()
	}
}

// CustomHeaders 自定义头部中间件
func CustomHeaders(headers map[string]string) gin.HandlerFunc {
	return func(c *gin.Context) {
		for key, value := range headers {
			c.Header(key, value)
		}
		c.Next()
	}
}

// ErrorHandler 错误处理中间件
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// 处理错误
		if len(c.Errors) > 0 {
			err := c.Errors.Last()
			logger.Errorf("Request error: %v", err)

			// 根据错误类型返回不同的状态码
			switch err.Type {
			case gin.ErrorTypeBind:
				c.JSON(http.StatusBadRequest, gin.H{
					"error": "Invalid request format",
					"code":  http.StatusBadRequest,
				})
			case gin.ErrorTypePublic:
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": err.Error(),
					"code":  http.StatusInternalServerError,
				})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Internal server error",
					"code":  http.StatusInternalServerError,
				})
			}
		}
	}
}

// RequestTrace 请求追踪中间件
func RequestTrace() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		traceID := generateTraceID()

		// 设置trace ID到上下文
		c.Set("trace_id", traceID)
		c.Header("X-Trace-ID", traceID)

		logger.Infof("Request started - TraceID: %s, Method: %s, Path: %s, IP: %s",
			traceID, c.Request.Method, c.Request.URL.Path, c.ClientIP())

		c.Next()

		duration := time.Since(start)
		logger.Infof("Request completed - TraceID: %s, Status: %d, Duration: %v",
			traceID, c.Writer.Status(), duration)
	}
}

// generateTraceID 生成追踪ID
func generateTraceID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Unix())
}
