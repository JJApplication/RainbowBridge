/*
   Project: RainbowBridge
   Github: https://github.com/landers1037
   Copyright Renj
*/

package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"rainbowbridge/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Level 日志级别
type Level string

const (
	// DEBUG_LEVEL 调试级别
	DEBUG_LEVEL Level = "DEBUG"
	// INFO_LEVEL 信息级别
	INFO_LEVEL Level = "INFO"
	// WARN_LEVEL 警告级别
	WARN_LEVEL Level = "WARN"
	// ERROR_LEVEL 错误级别
	ERROR_LEVEL Level = "ERROR"
	// FATAL_LEVEL 致命错误级别
	FATAL_LEVEL Level = "FATAL"
)

// Config 日志配置
type Config struct {
	// Level 日志级别
	Level Level `json:"level"`
	// Format 日志格式 json/console
	Format string `json:"format"`
	// Output 输出方式 file/console/both
	Output string `json:"output"`
	// Filename 日志文件名
	Filename string `json:"filename"`
	// MaxSize 单个日志文件最大大小(MB)
	MaxSize int `json:"max_size"`
	// MaxAge 日志文件保留天数
	MaxAge int `json:"max_age"`
	// MaxBackups 最大备份文件数
	MaxBackups int `json:"max_backups"`
	// Compress 是否压缩备份文件
	Compress bool `json:"compress"`
	// EnableCaller 是否启用调用者信息
	EnableCaller bool `json:"enable_caller"`
	// EnableStacktrace 是否启用堆栈跟踪
	EnableStacktrace bool `json:"enable_stacktrace"`
}

// Logger 日志器
type Logger struct {
	// *zap.Logger zap日志器指针，用于高性能日志记录
	zapLogger *zap.Logger
	// *zap.SugaredLogger 糖化日志器指针，用于便捷的日志记录
	sugarLogger *zap.SugaredLogger
	// config 日志配置指针，用于存储日志配置信息
	config *Config
}

// defaultConfig 默认配置
var defaultConfig = &Config{
	Level:            INFO_LEVEL,
	Format:           "json",
	Output:           "both",
	Filename:         "logs/rainbowbridge.log",
	MaxSize:          100,
	MaxAge:           30,
	MaxBackups:       10,
	Compress:         true,
	EnableCaller:     true,
	EnableStacktrace: true,
}

// globalLogger 全局日志器
var globalLogger *Logger

// NewLogger 创建新的日志器
func NewLogger(config *Config) (*Logger, error) {
	if config == nil {
		config = defaultConfig
	}

	// 创建日志目录
	logDir := filepath.Dir(config.Filename)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("%w: create log directory failed: %v", errors.ErrLoggerInitFailed, err)
	}

	// 配置编码器
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// 选择编码器
	var encoder zapcore.Encoder
	if strings.ToLower(config.Format) == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// 配置日志级别
	level := getZapLevel(config.Level)

	// 配置输出
	var cores []zapcore.Core

	// 文件输出
	if config.Output == "file" || config.Output == "both" {
		fileWriter := &lumberjack.Logger{
			Filename:   config.Filename,
			MaxSize:    config.MaxSize,
			MaxAge:     config.MaxAge,
			MaxBackups: config.MaxBackups,
			Compress:   config.Compress,
		}
		cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(fileWriter), level))
	}

	// 控制台输出
	if config.Output == "console" || config.Output == "both" {
		cores = append(cores, zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), level))
	}

	// 创建核心
	core := zapcore.NewTee(cores...)

	// 配置选项
	options := make([]zap.Option, 0, 3)
	if config.EnableCaller {
		options = append(options, zap.AddCaller())
	}
	if config.EnableStacktrace {
		options = append(options, zap.AddStacktrace(zapcore.ErrorLevel))
	}
	options = append(options, zap.AddCallerSkip(1))

	// 创建日志器
	zapLogger := zap.New(core, options...)
	sugarLogger := zapLogger.Sugar()

	logger := &Logger{
		zapLogger:   zapLogger,
		sugarLogger: sugarLogger,
		config:      config,
	}

	return logger, nil
}

// getZapLevel 获取zap日志级别
func getZapLevel(level Level) zapcore.Level {
	switch level {
	case DEBUG_LEVEL:
		return zapcore.DebugLevel
	case INFO_LEVEL:
		return zapcore.InfoLevel
	case WARN_LEVEL:
		return zapcore.WarnLevel
	case ERROR_LEVEL:
		return zapcore.ErrorLevel
	case FATAL_LEVEL:
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}

// InitGlobalLogger 初始化全局日志器
func InitGlobalLogger(config *Config) error {
	logger, err := NewLogger(config)
	if err != nil {
		return err
	}
	globalLogger = logger
	return nil
}

// GetGlobalLogger 获取全局日志器
func GetGlobalLogger() *Logger {
	return globalLogger
}

// Debug 调试日志
func (l *Logger) Debug(msg string, fields ...zap.Field) {
	l.zapLogger.Debug(msg, fields...)
}

// Info 信息日志
func (l *Logger) Info(msg string, fields ...zap.Field) {
	l.zapLogger.Info(msg, fields...)
}

// Warn 警告日志
func (l *Logger) Warn(msg string, fields ...zap.Field) {
	l.zapLogger.Warn(msg, fields...)
}

// Error 错误日志
func (l *Logger) Error(msg string, fields ...zap.Field) {
	l.zapLogger.Error(msg, fields...)
}

// Fatal 致命错误日志
func (l *Logger) Fatal(msg string, fields ...zap.Field) {
	l.zapLogger.Fatal(msg, fields...)
}

// Debugf 格式化调试日志
func (l *Logger) Debugf(template string, args ...interface{}) {
	l.sugarLogger.Debugf(template, args...)
}

// Infof 格式化信息日志
func (l *Logger) Infof(template string, args ...interface{}) {
	l.sugarLogger.Infof(template, args...)
}

// Warnf 格式化警告日志
func (l *Logger) Warnf(template string, args ...interface{}) {
	l.sugarLogger.Warnf(template, args...)
}

// Errorf 格式化错误日志
func (l *Logger) Errorf(template string, args ...interface{}) {
	l.sugarLogger.Errorf(template, args...)
}

// Fatalf 格式化致命错误日志
func (l *Logger) Fatalf(template string, args ...interface{}) {
	l.sugarLogger.Fatalf(template, args...)
}

// With 添加字段
func (l *Logger) With(fields ...zap.Field) *Logger {
	// 将 zap.Field 转换为 interface{} 用于 sugar logger
	sugarFields := make([]interface{}, len(fields)*2)
	for i, field := range fields {
		sugarFields[i*2] = field.Key
		sugarFields[i*2+1] = field.Interface
	}
	
	return &Logger{
		zapLogger:   l.zapLogger.With(fields...),
		sugarLogger: l.zapLogger.Sugar().With(sugarFields...),
		config:      l.config,
	}
}

// Sync 同步日志
func (l *Logger) Sync() error {
	if err := l.zapLogger.Sync(); err != nil {
		return fmt.Errorf("%w: %v", errors.ErrLoggerWriteFailed, err)
	}
	return nil
}

// Close 关闭日志器
func (l *Logger) Close() error {
	return l.Sync()
}

// 全局日志函数

// Debug 全局调试日志
func Debug(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.Debug(msg, fields...)
	}
}

// Info 全局信息日志
func Info(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.Info(msg, fields...)
	}
}

// Warn 全局警告日志
func Warn(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.Warn(msg, fields...)
	}
}

// Error 全局错误日志
func Error(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.Error(msg, fields...)
	}
}

// Fatal 全局致命错误日志
func Fatal(msg string, fields ...zap.Field) {
	if globalLogger != nil {
		globalLogger.Fatal(msg, fields...)
	}
}

// Debugf 全局格式化调试日志
func Debugf(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Debugf(template, args...)
	}
}

// Infof 全局格式化信息日志
func Infof(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Infof(template, args...)
	}
}

// Warnf 全局格式化警告日志
func Warnf(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Warnf(template, args...)
	}
}

// Errorf 全局格式化错误日志
func Errorf(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Errorf(template, args...)
	}
}

// Fatalf 全局格式化致命错误日志
func Fatalf(template string, args ...interface{}) {
	if globalLogger != nil {
		globalLogger.Fatalf(template, args...)
	}
}

// Sync 全局同步日志
func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}
