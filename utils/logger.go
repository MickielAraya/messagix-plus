package utils

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

type ColorLogger struct {
	Info    func(string, ...interface{})
	Warn    func(string, ...interface{})
	Error   func(string, ...interface{})
	Success func(string, ...interface{})
}

func NewColorLogger() *ColorLogger {
	return &ColorLogger{
		Info:    createLogger(color.New(color.FgCyan)),
		Warn:    createLogger(color.New(color.FgYellow)),
		Error:   createLogger(color.New(color.FgRed)),
		Success: createLogger(color.New(color.FgHiGreen)),
	}
}

func createLogger(c *color.Color) func(string, ...interface{}) {
	return func(format string, args ...interface{}) {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		message := fmt.Sprintf(format, args...)
		c.Printf("[%s] %s\n", timestamp, message)
	}
}

var (
	Log = NewColorLogger()
)
