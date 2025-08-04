/*
   Project: RainbowBridge
   Github: https://github.com/landers1037
   Copyright Renj
*/

package configer

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fsnotify/fsnotify"
	"rainbowbridge/pkg/errors"
)

// Config 主配置结构体
type Config struct {
	// Debug 调试模式
	Debug bool `toml:"debug" json:"debug"`
	// LogLevel 日志级别
	LogLevel string `toml:"logLevel" json:"log_level"`
	// InsecureSkipVerify 跳过TLS验证
	InsecureSkipVerify bool `toml:"InsecureSkipVerify" json:"insecure_skip_verify"`
	// DefaultEntryPoints 默认入口点
	DefaultEntryPoints []string `toml:"defaultEntryPoints" json:"default_entry_points"`
	// EntryPoints 入口点配置
	EntryPoints map[string]*EntryPoint `toml:"entryPoints" json:"entry_points"`
	// TLS TLS配置
	TLS *TLSConfig `toml:"tls" json:"tls"`
	// HTTP HTTP配置
	HTTP *HTTPConfig `toml:"http" json:"http"`
	// Providers 提供者配置
	Providers *ProvidersConfig `toml:"providers" json:"providers"`
}

// EntryPoint 入口点配置
type EntryPoint struct {
	// Address 监听地址
	Address string `toml:"address" json:"address"`
}

// TLSConfig TLS配置
type TLSConfig struct {
	// Certificates 证书配置
	Certificates map[string]*CertificateConfig `toml:"certificates" json:"certificates"`
}

// CertificateConfig 证书配置
type CertificateConfig struct {
	// CertFile 证书文件路径
	CertFile string `toml:"certFile" json:"cert_file"`
	// KeyFile 私钥文件路径
	KeyFile string `toml:"keyFile" json:"key_file"`
}

// HTTPConfig HTTP配置
type HTTPConfig struct {
	// Routers 路由配置
	Routers map[string]*RouterConfig `toml:"routers" json:"routers"`
	// Services 服务配置
	Services map[string]*ServiceConfig `toml:"services" json:"services"`
	// Middlewares 中间件配置
	Middlewares map[string]*MiddlewareConfig `toml:"middlewares" json:"middlewares"`
}

// RouterConfig 路由配置
type RouterConfig struct {
	// EntryPoints 入口点
	EntryPoints []string `toml:"entryPoints" json:"entry_points"`
	// Rule 路由规则
	Rule string `toml:"rule" json:"rule"`
	// Middlewares 中间件列表
	Middlewares []string `toml:"middlewares" json:"middlewares"`
	// TLS 是否启用TLS
	TLS bool `toml:"tls" json:"tls"`
	// Service 服务名称
	Service string `toml:"service" json:"service"`
}

// ServiceConfig 服务配置
type ServiceConfig struct {
	// LoadBalancer 负载均衡配置
	LoadBalancer *LoadBalancerConfig `toml:"loadBalancer" json:"load_balancer"`
}

// LoadBalancerConfig 负载均衡配置
type LoadBalancerConfig struct {
	// Servers 服务器列表
	Servers []*ServerConfig `toml:"servers" json:"servers"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	// URL 服务器URL
	URL string `toml:"url" json:"url"`
}

// MiddlewareConfig 中间件配置
type MiddlewareConfig struct {
	// RedirectScheme 重定向配置
	RedirectScheme *RedirectSchemeConfig `toml:"redirectScheme" json:"redirect_scheme"`
	// Compress 压缩配置
	Compress *CompressConfig `toml:"compress" json:"compress"`
	// Errors 错误处理配置
	Errors *ErrorsConfig `toml:"errors" json:"errors"`
	// Buffering 缓冲配置
	Buffering *BufferingConfig `toml:"buffering" json:"buffering"`
	// Headers 头部配置
	Headers *HeadersConfig `toml:"headers" json:"headers"`
}

// RedirectSchemeConfig 重定向配置
type RedirectSchemeConfig struct {
	// Scheme 重定向协议
	Scheme string `toml:"scheme" json:"scheme"`
	// Permanent 是否永久重定向
	Permanent bool `toml:"permanent" json:"permanent"`
}

// CompressConfig 压缩配置
type CompressConfig struct {
	// ExcludedContentTypes 排除的内容类型
	ExcludedContentTypes []string `toml:"excludedContentTypes" json:"excluded_content_types"`
	// MinResponseBodyBytes 最小响应体字节数
	MinResponseBodyBytes int64 `toml:"minResponseBodyBytes" json:"min_response_body_bytes"`
	// DefaultEncoding 默认编码
	DefaultEncoding string `toml:"defaultEncoding" json:"default_encoding"`
}

// ErrorsConfig 错误处理配置
type ErrorsConfig struct {
	// Status 状态码列表
	Status []string `toml:"status" json:"status"`
	// Service 错误处理服务
	Service string `toml:"service" json:"service"`
}

// BufferingConfig 缓冲配置
type BufferingConfig struct {
	// MaxRequestBodyBytes 最大请求体字节数
	MaxRequestBodyBytes int64 `toml:"maxRequestBodyBytes" json:"max_request_body_bytes"`
}

// HeadersConfig 头部配置
type HeadersConfig struct {
	// CustomResponseHeaders 自定义响应头
	CustomResponseHeaders map[string]string `toml:"customResponseHeaders" json:"custom_response_headers"`
}

// ProvidersConfig 提供者配置
type ProvidersConfig struct {
	// File 文件提供者配置
	File *FileProviderConfig `toml:"file" json:"file"`
}

// FileProviderConfig 文件提供者配置
type FileProviderConfig struct {
	// Filename 配置文件名
	Filename string `toml:"filename" json:"filename"`
}

// Manager 配置管理器
type Manager struct {
	// *Config 配置指针，用于快速访问配置内容
	config *Config
	// configFile 配置文件路径
	configFile string
	// watcher 文件监听器指针，用于监听配置文件变化
	watcher *fsnotify.Watcher
	// mutex 读写锁，用于保护配置的并发访问
	mutex sync.RWMutex
	// reloadCallbacks 重载回调函数列表
	reloadCallbacks []func(*Config)
}

// NewManager 创建配置管理器
func NewManager(configFile string) (*Manager, error) {
	manager := &Manager{
		configFile:      configFile,
		reloadCallbacks: make([]func(*Config), 0),
	}

	if err := manager.loadConfig(); err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrConfigParseError, err)
	}

	if err := manager.startWatcher(); err != nil {
		return nil, fmt.Errorf("start config watcher failed: %v", err)
	}

	return manager, nil
}

// loadConfig 加载配置文件
func (m *Manager) loadConfig() error {
	if _, err := os.Stat(m.configFile); os.IsNotExist(err) {
		return errors.ErrConfigFileNotFound
	}

	var config Config
	if _, err := toml.DecodeFile(m.configFile, &config); err != nil {
		return fmt.Errorf("%w: %v", errors.ErrConfigParseError, err)
	}

	m.mutex.Lock()
	m.config = &config
	m.mutex.Unlock()

	return nil
}

// startWatcher 启动文件监听器
func (m *Manager) startWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	m.watcher = watcher

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					// 延迟重载，避免频繁重载
					time.Sleep(100 * time.Millisecond)
					if err := m.reloadConfig(); err != nil {
						// 这里应该使用日志记录错误
						fmt.Printf("Config reload failed: %v\n", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				// 这里应该使用日志记录错误
				fmt.Printf("Config watcher error: %v\n", err)
			}
		}
	}()

	err = watcher.Add(m.configFile)
	if err != nil {
		return err
	}

	return nil
}

// reloadConfig 重载配置
func (m *Manager) reloadConfig() error {
	oldConfig := m.GetConfig()

	if err := m.loadConfig(); err != nil {
		return fmt.Errorf("%w: %v", errors.ErrConfigReloadFailed, err)
	}

	newConfig := m.GetConfig()

	// 执行重载回调
	for _, callback := range m.reloadCallbacks {
		callback(newConfig)
	}

	// 这里应该使用日志记录
	fmt.Printf("Config reloaded successfully, old debug: %v, new debug: %v\n", oldConfig.Debug, newConfig.Debug)

	return nil
}

// GetConfig 获取配置
func (m *Manager) GetConfig() *Config {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.config
}

// AddReloadCallback 添加重载回调
func (m *Manager) AddReloadCallback(callback func(*Config)) {
	m.reloadCallbacks = append(m.reloadCallbacks, callback)
}

// Close 关闭配置管理器
func (m *Manager) Close() error {
	if m.watcher != nil {
		return m.watcher.Close()
	}
	return nil
}