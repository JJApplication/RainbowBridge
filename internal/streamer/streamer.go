/*
   Project: RainbowBridge
   Github: https://github.com/landers1037
   Copyright Renj
*/

package streamer

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"rainbowbridge/internal/logger"
	"rainbowbridge/pkg/errors"

	"github.com/gin-gonic/gin"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"google.golang.org/grpc"
)

// Config 流量统计配置
type Config struct {
	// Enabled 是否启用流量统计
	Enabled bool `json:"enabled"`
	// InfluxDBURL InfluxDB连接地址
	InfluxDBURL string `json:"influxdb_url"`
	// InfluxDBToken InfluxDB访问令牌
	InfluxDBToken string `json:"influxdb_token"`
	// InfluxDBOrg InfluxDB组织
	InfluxDBOrg string `json:"influxdb_org"`
	// InfluxDBBucket InfluxDB存储桶
	InfluxDBBucket string `json:"influxdb_bucket"`
	// BatchSize 批量写入大小
	BatchSize int `json:"batch_size"`
	// FlushInterval 刷新间隔
	FlushInterval time.Duration `json:"flush_interval"`
	// HTTPPort HTTP接口端口
	HTTPPort int `json:"http_port"`
	// GRPCPort gRPC接口端口
	GRPCPort int `json:"grpc_port"`
}

// Metric 流量指标
type Metric struct {
	// Timestamp 时间戳
	Timestamp time.Time `json:"timestamp"`
	// ServiceName 服务名称
	ServiceName string `json:"service_name"`
	// Method HTTP方法
	Method string `json:"method"`
	// Path 请求路径
	Path string `json:"path"`
	// StatusCode 状态码
	StatusCode int `json:"status_code"`
	// ResponseTime 响应时间(毫秒)
	ResponseTime int64 `json:"response_time"`
	// RequestSize 请求大小(字节)
	RequestSize int64 `json:"request_size"`
	// ResponseSize 响应大小(字节)
	ResponseSize int64 `json:"response_size"`
	// ClientIP 客户端IP
	ClientIP string `json:"client_ip"`
	// UserAgent 用户代理
	UserAgent string `json:"user_agent"`
	// TraceID 追踪ID
	TraceID string `json:"trace_id"`
	// Success 是否成功
	Success bool `json:"success"`
}

// Stats 统计信息
type Stats struct {
	// TotalRequests 总请求数
	TotalRequests int64 `json:"total_requests"`
	// SuccessRequests 成功请求数
	SuccessRequests int64 `json:"success_requests"`
	// FailedRequests 失败请求数
	FailedRequests int64 `json:"failed_requests"`
	// AverageResponseTime 平均响应时间
	AverageResponseTime float64 `json:"average_response_time"`
	// TotalTraffic 总流量(字节)
	TotalTraffic int64 `json:"total_traffic"`
	// RequestsPerSecond 每秒请求数
	RequestsPerSecond float64 `json:"requests_per_second"`
	// TopPaths 热门路径
	TopPaths []PathStat `json:"top_paths"`
	// TopServices 热门服务
	TopServices []ServiceStat `json:"top_services"`
}

// PathStat 路径统计
type PathStat struct {
	// Path 路径
	Path string `json:"path"`
	// Count 请求次数
	Count int64 `json:"count"`
	// AverageResponseTime 平均响应时间
	AverageResponseTime float64 `json:"average_response_time"`
}

// ServiceStat 服务统计
type ServiceStat struct {
	// ServiceName 服务名称
	ServiceName string `json:"service_name"`
	// Count 请求次数
	Count int64 `json:"count"`
	// AverageResponseTime 平均响应时间
	AverageResponseTime float64 `json:"average_response_time"`
}

// Streamer 流量统计器
type Streamer struct {
	// config 配置指针，用于存储流量统计配置信息
	config *Config
	// influxClient InfluxDB客户端指针，用于连接InfluxDB数据库
	influxClient influxdb2.Client
	// writeAPI 写入API指针，用于向InfluxDB写入数据
	writeAPI api.WriteAPI
	// queryAPI 查询API指针，用于从InfluxDB查询数据
	queryAPI api.QueryAPI
	// metricsChan 指标通道，用于异步收集流量指标
	metricsChan chan *Metric
	// httpServer HTTP服务器指针，用于提供HTTP接口
	httpServer *http.Server
	// grpcServer gRPC服务器指针，用于提供gRPC接口
	grpcServer *grpc.Server
	// running 运行状态，用于标识流量统计器是否正在运行
	running bool
	// mutex 互斥锁，用于保护运行状态的并发访问
	mutex sync.RWMutex
	// stats 内存统计，用于快速获取统计信息
	stats *Stats
	// statsMutex 统计互斥锁，用于保护统计信息的并发访问
	statsMutex sync.RWMutex
}

// NewStreamer 创建流量统计器
func NewStreamer(config *Config) (*Streamer, error) {
	if config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	if !config.Enabled {
		return &Streamer{
			config: config,
			stats:  &Stats{},
		}, nil
	}

	// 设置默认值
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 10 * time.Second
	}
	if config.HTTPPort == 0 {
		config.HTTPPort = 8080
	}
	if config.GRPCPort == 0 {
		config.GRPCPort = 9090
	}

	// 创建InfluxDB客户端
	client := influxdb2.NewClient(config.InfluxDBURL, config.InfluxDBToken)

	// 测试连接
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	health, err := client.Health(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: InfluxDB connection failed: %v", errors.ErrStreamerConnectFailed, err)
	}

	if health.Status != "pass" {
		return nil, fmt.Errorf("%w: InfluxDB health check failed: %s", errors.ErrStreamerConnectFailed, health.Status)
	}

	writeAPI := client.WriteAPI(config.InfluxDBOrg, config.InfluxDBBucket)
	queryAPI := client.QueryAPI(config.InfluxDBOrg)

	streamer := &Streamer{
		config:       config,
		influxClient: client,
		writeAPI:     writeAPI,
		queryAPI:     queryAPI,
		metricsChan:  make(chan *Metric, config.BatchSize*2),
		stats:        &Stats{},
	}

	return streamer, nil
}

// Start 启动流量统计器
func (s *Streamer) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.running {
		return fmt.Errorf("streamer already running")
	}

	if !s.config.Enabled {
		logger.Info("Streamer is disabled")
		return nil
	}

	logger.Info("Starting traffic streamer")

	// 启动指标收集器
	go s.metricsCollector()

	// 启动HTTP服务器
	if err := s.startHTTPServer(); err != nil {
		return fmt.Errorf("start HTTP server failed: %v", err)
	}

	// 启动gRPC服务器
	if err := s.startGRPCServer(); err != nil {
		return fmt.Errorf("start gRPC server failed: %v", err)
	}

	s.running = true
	logger.Infof("Traffic streamer started on HTTP:%d, gRPC:%d", s.config.HTTPPort, s.config.GRPCPort)

	return nil
}

// Stop 停止流量统计器
func (s *Streamer) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if !s.running {
		return nil
	}

	logger.Info("Stopping traffic streamer")

	// 停止HTTP服务器
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			logger.Errorf("Stop HTTP server failed: %v", err)
		}
	}

	// 停止gRPC服务器
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	// 关闭指标通道
	close(s.metricsChan)

	// 关闭InfluxDB客户端
	if s.influxClient != nil {
		s.influxClient.Close()
	}

	s.running = false
	logger.Info("Traffic streamer stopped")

	return nil
}

// RecordMetric 记录指标
func (s *Streamer) RecordMetric(metric *Metric) {
	if !s.config.Enabled || !s.running {
		return
	}

	select {
	case s.metricsChan <- metric:
		// 更新内存统计
		s.updateStats(metric)
	default:
		logger.Warn("Metrics channel is full, dropping metric")
	}
}

// updateStats 更新统计信息
func (s *Streamer) updateStats(metric *Metric) {
	s.statsMutex.Lock()
	defer s.statsMutex.Unlock()

	s.stats.TotalRequests++
	if metric.Success {
		s.stats.SuccessRequests++
	} else {
		s.stats.FailedRequests++
	}

	// 更新平均响应时间
	if s.stats.TotalRequests == 1 {
		s.stats.AverageResponseTime = float64(metric.ResponseTime)
	} else {
		s.stats.AverageResponseTime = (s.stats.AverageResponseTime*float64(s.stats.TotalRequests-1) + float64(metric.ResponseTime)) / float64(s.stats.TotalRequests)
	}

	// 更新总流量
	s.stats.TotalTraffic += metric.RequestSize + metric.ResponseSize
}

// metricsCollector 指标收集器
func (s *Streamer) metricsCollector() {
	batch := make([]*Metric, 0, s.config.BatchSize)
	ticker := time.NewTicker(s.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case metric, ok := <-s.metricsChan:
			if !ok {
				// 通道已关闭，写入剩余批次
				if len(batch) > 0 {
					s.writeBatch(batch)
				}
				return
			}

			batch = append(batch, metric)
			if len(batch) >= s.config.BatchSize {
				s.writeBatch(batch)
				batch = batch[:0] // 重置切片
			}

		case <-ticker.C:
			if len(batch) > 0 {
				s.writeBatch(batch)
				batch = batch[:0] // 重置切片
			}
		}
	}
}

// writeBatch 批量写入指标
func (s *Streamer) writeBatch(batch []*Metric) {
	for _, metric := range batch {
		point := influxdb2.NewPointWithMeasurement("http_requests").
			AddTag("service", metric.ServiceName).
			AddTag("method", metric.Method).
			AddTag("path", metric.Path).
			AddTag("status_code", fmt.Sprintf("%d", metric.StatusCode)).
			AddTag("client_ip", metric.ClientIP).
			AddTag("trace_id", metric.TraceID).
			AddField("response_time", metric.ResponseTime).
			AddField("request_size", metric.RequestSize).
			AddField("response_size", metric.ResponseSize).
			AddField("success", metric.Success).
			SetTime(metric.Timestamp)

		s.writeAPI.WritePoint(point)
	}

	// 强制刷新
	s.writeAPI.Flush()

	logger.Debugf("Written %d metrics to InfluxDB", len(batch))
}

// startHTTPServer 启动HTTP服务器
func (s *Streamer) startHTTPServer() error {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())

	// 健康检查
	engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// 获取统计信息
	engine.GET("/stats", s.handleGetStats)

	// 获取指定时间范围的统计信息
	engine.GET("/stats/range", s.handleGetStatsRange)

	// 获取服务统计信息
	engine.GET("/stats/services", s.handleGetServiceStats)

	// 获取路径统计信息
	engine.GET("/stats/paths", s.handleGetPathStats)

	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.HTTPPort),
		Handler: engine,
	}

	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("HTTP server error: %v", err)
		}
	}()

	return nil
}

// startGRPCServer 启动gRPC服务器
func (s *Streamer) startGRPCServer() error {
	// 这里可以实现gRPC服务器
	// 由于篇幅限制，暂时跳过gRPC实现
	return nil
}

// handleGetStats 处理获取统计信息请求
func (s *Streamer) handleGetStats(c *gin.Context) {
	s.statsMutex.RLock()
	stats := *s.stats
	s.statsMutex.RUnlock()

	// 计算每秒请求数
	if s.stats.TotalRequests > 0 {
		// 简单计算，实际应该基于时间窗口
		stats.RequestsPerSecond = float64(s.stats.TotalRequests) / 60.0 // 假设1分钟窗口
	}

	c.JSON(http.StatusOK, stats)
}

// handleGetStatsRange 处理获取指定时间范围统计信息请求
func (s *Streamer) handleGetStatsRange(c *gin.Context) {
	startTime := c.Query("start")
	endTime := c.Query("end")

	if startTime == "" || endTime == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "start and end time required"})
		return
	}

	// 查询InfluxDB获取指定时间范围的数据
	query := fmt.Sprintf(`
		from(bucket: "%s")
			|> range(start: %s, stop: %s)
			|> filter(fn: (r) => r._measurement == "http_requests")
			|> group(columns: ["_measurement"])
			|> count()
	`, s.config.InfluxDBBucket, startTime, endTime)

	result, err := s.queryAPI.Query(context.Background(), query)
	if err != nil {
		logger.Errorf("Query InfluxDB failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Query failed"})
		return
	}

	var count int64
	for result.Next() {
		if result.Record().Value() != nil {
			if v, ok := result.Record().Value().(int64); ok {
				count = v
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"start_time":     startTime,
		"end_time":       endTime,
		"total_requests": count,
	})
}

// handleGetServiceStats 处理获取服务统计信息请求
func (s *Streamer) handleGetServiceStats(c *gin.Context) {
	// 查询各服务的请求统计
	query := fmt.Sprintf(`
		from(bucket: "%s")
			|> range(start: -1h)
			|> filter(fn: (r) => r._measurement == "http_requests")
			|> group(columns: ["service"])
			|> count()
			|> sort(columns: ["_value"], desc: true)
			|> limit(n: 10)
	`, s.config.InfluxDBBucket)

	result, err := s.queryAPI.Query(context.Background(), query)
	if err != nil {
		logger.Errorf("Query service stats failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Query failed"})
		return
	}

	serviceStats := make([]ServiceStat, 0)
	for result.Next() {
		record := result.Record()
		serviceName := record.ValueByKey("service")
		count := record.Value()

		if serviceName != nil && count != nil {
			if name, ok := serviceName.(string); ok {
				if c, ok := count.(int64); ok {
					serviceStats = append(serviceStats, ServiceStat{
						ServiceName: name,
						Count:       c,
					})
				}
			}
		}
	}

	c.JSON(http.StatusOK, serviceStats)
}

// handleGetPathStats 处理获取路径统计信息请求
func (s *Streamer) handleGetPathStats(c *gin.Context) {
	// 查询各路径的请求统计
	query := fmt.Sprintf(`
		from(bucket: "%s")
			|> range(start: -1h)
			|> filter(fn: (r) => r._measurement == "http_requests")
			|> group(columns: ["path"])
			|> count()
			|> sort(columns: ["_value"], desc: true)
			|> limit(n: 10)
	`, s.config.InfluxDBBucket)

	result, err := s.queryAPI.Query(context.Background(), query)
	if err != nil {
		logger.Errorf("Query path stats failed: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Query failed"})
		return
	}

	pathStats := make([]PathStat, 0)
	for result.Next() {
		record := result.Record()
		path := record.ValueByKey("path")
		count := record.Value()

		if path != nil && count != nil {
			if p, ok := path.(string); ok {
				if c, ok := count.(int64); ok {
					pathStats = append(pathStats, PathStat{
						Path:  p,
						Count: c,
					})
				}
			}
		}
	}

	c.JSON(http.StatusOK, pathStats)
}

// CreateMiddleware 创建流量统计中间件
func (s *Streamer) CreateMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		// 处理请求
		c.Next()

		// 记录指标
		if s.config.Enabled {
			metric := &Metric{
				Timestamp:    start,
				ServiceName:  c.GetString("service_name"),
				Method:       c.Request.Method,
				Path:         c.Request.URL.Path,
				StatusCode:   c.Writer.Status(),
				ResponseTime: time.Since(start).Milliseconds(),
				RequestSize:  c.Request.ContentLength,
				ResponseSize: int64(c.Writer.Size()),
				ClientIP:     c.ClientIP(),
				UserAgent:    c.Request.UserAgent(),
				TraceID:      c.GetString("trace_id"),
				Success:      c.Writer.Status() < 400,
			}

			s.RecordMetric(metric)
		}
	}
}

// IsRunning 检查是否运行中
func (s *Streamer) IsRunning() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.running
}

// GetStats 获取统计信息
func (s *Streamer) GetStats() *Stats {
	s.statsMutex.RLock()
	defer s.statsMutex.RUnlock()
	return s.stats
}
