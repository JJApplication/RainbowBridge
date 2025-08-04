/*
   Project: RainbowBridge
   Github: https://github.com/landers1037
   Copyright Renj
*/

package errors

import "errors"

// Gateway相关错误
var (
	// ErrGatewayStartFailed 网关启动失败
	ErrGatewayStartFailed = errors.New("Gateway start failed")
	// ErrGatewayConfigInvalid 网关配置无效
	ErrGatewayConfigInvalid = errors.New("Gateway config invalid")
	// ErrGatewayServiceNotFound 网关服务未找到
	ErrGatewayServiceNotFound = errors.New("Gateway service not found")
)

// Server相关错误
var (
	// ErrServerStartFailed 服务器启动失败
	ErrServerStartFailed = errors.New("Server start failed")
	// ErrServerStopFailed 服务器停止失败
	ErrServerStopFailed = errors.New("Server stop failed")
	// ErrServerConfigInvalid 服务器配置无效
	ErrServerConfigInvalid = errors.New("Server config invalid")
)

// Proxy相关错误
var (
	// ErrProxyTargetUnreachable 代理目标不可达
	ErrProxyTargetUnreachable = errors.New("Proxy target unreachable")
	// ErrProxyConfigInvalid 代理配置无效
	ErrProxyConfigInvalid = errors.New("Proxy config invalid")
	// ErrProxyProtocolNotSupported 代理协议不支持
	ErrProxyProtocolNotSupported = errors.New("Proxy protocol not supported")
)

// Config相关错误
var (
	// ErrConfigFileNotFound 配置文件未找到
	ErrConfigFileNotFound = errors.New("Config file not found")
	// ErrConfigParseError 配置解析错误
	ErrConfigParseError = errors.New("Config parse error")
	// ErrConfigReloadFailed 配置重载失败
	ErrConfigReloadFailed = errors.New("Config reload failed")
)

// Logger相关错误
var (
	// ErrLoggerInitFailed 日志初始化失败
	ErrLoggerInitFailed = errors.New("Logger init failed")
	// ErrLoggerWriteFailed 日志写入失败
	ErrLoggerWriteFailed = errors.New("Logger write failed")
)

// Middleware相关错误
var (
	// ErrMiddlewareConfigInvalid 中间件配置无效
	ErrMiddlewareConfigInvalid = errors.New("Middleware config invalid")
	// ErrMiddlewareExecuteFailed 中间件执行失败
	ErrMiddlewareExecuteFailed = errors.New("Middleware execute failed")
)

// Streamer相关错误
var (
	// ErrStreamerConnectFailed 流量统计连接失败
	ErrStreamerConnectFailed = errors.New("Streamer connect failed")
	// ErrStreamerWriteFailed 流量统计写入失败
	ErrStreamerWriteFailed = errors.New("Streamer write failed")
)