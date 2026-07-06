package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var log *zap.SugaredLogger

func Init(debug bool) error {
	var cfg zap.Config
	if debug {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.TimeKey = "timestamp"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	logger, err := cfg.Build()
	if err != nil {
		return err
	}
	log = logger.Sugar()
	return nil
}

func L() *zap.SugaredLogger {
	if log == nil {
		_ = Init(false)
	}
	return log
}

func With(fields ...interface{}) *zap.SugaredLogger {
	return log.With(fields...)
}

func Sync() {
	if log != nil {
		_ = log.Sync()
	}
}
