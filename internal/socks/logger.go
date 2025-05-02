package socks

import "github.com/hupe1980/golog"

type Logger struct {
	logger golog.Logger
}

func (l *Logger) logf(level golog.Level, format string, args ...any) {
	l.logger.Printf(level, format, args...)
}

func (l *Logger) logDebugf(format string, args ...any) {
	l.logf(golog.DEBUG, format, args...)
}

func (l *Logger) logInfof(format string, args ...any) {
	l.logf(golog.INFO, format, args...)
}

func (l *Logger) logErrorf(format string, args ...any) {
	l.logf(golog.ERROR, format, args...)
}
