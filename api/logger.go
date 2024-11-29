package api

import (
    lg "log"

    "github.com/gin-gonic/gin"
)

var log = NewLogger()

type Logger struct {
}

func NewLogger() Logger {
    lg.SetFlags(lg.LstdFlags)
    return Logger{}
}

func (l Logger) Infof(format string, args ...interface{}) {
    lg.Printf("[INFO] "+format, args...)
}

func (l Logger) Errorf(format string, args ...interface{}) {
    lg.Printf("[ERROR] "+format, args...)
}

func (l Logger) Debugf(format string, args ...interface{}) {
    if gin.ReleaseMode != gin.Mode() {
        lg.Printf("[DEBUG] "+format, args...)
    }
}

func (l Logger) Fatalf(format string, args ...interface{}) {
    lg.Fatalf("[FATAL] "+format, args...)
}

func (l Logger) Panicf(format string, args ...interface{}) {
    lg.Panicf("[PANIC] "+format, args...)
}
