package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Logger struct {
	dir       string
	file      *os.File
	mu        sync.Mutex
	currentDate string
	uid       int
	gid       int
	pruneDays int
}

func NewLogger(dir string, uid, gid, pruneDays int) (*Logger, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	logger := &Logger{
		dir:       dir,
		uid:       uid,
		gid:       gid,
		pruneDays: pruneDays,
	}

	return logger, nil
}

func (l *Logger) Write(topic string, message string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	date := getDate()
	if l.currentDate != date {
		if err := l.rotate(date); err != nil {
			return err
		}
	}

	// Format: HH:MM:SS (not full ISO timestamp)
	timestamp := time.Now().Format("15:04:05")

	// Format message with optional topic
	var msg string
	if topic != "" {
		msg = fmt.Sprintf("[%s] %s", topic, strings.TrimSpace(message))
	} else {
		msg = strings.TrimSpace(message)
	}

	if msg == "" {
		return nil
	}

	// Calculate prefix for multi-line continuation
	// Prefix is: newline + 9 spaces (for time + space) + topic length with brackets if present
	prefixLen := 9
	if topic != "" {
		prefixLen += len(topic) + 3 // [topic] = topic + 3 chars
	}
	prefix := "\n" + strings.Repeat(" ", prefixLen)

	// Replace newlines in message with proper indentation
	formattedMsg := strings.ReplaceAll(msg, "\n", prefix)

	output := fmt.Sprintf("%s %s\n", timestamp, formattedMsg)

	_, err := l.file.WriteString(output)
	if err != nil {
		return err
	}

	return l.file.Sync()
}

func (l *Logger) rotate(date string) error {
	// Close current file if open
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}

	// Open new log file
	logPath := filepath.Join(l.dir, date+".log")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	// Set ownership if running as root
	if os.Geteuid() == 0 && (l.uid > 0 || l.gid > 0) {
		syscall.Chown(logPath, l.uid, l.gid)
	}

	l.file = file
	l.currentDate = date

	// Clean up old log files if pruning is enabled
	if l.pruneDays > 0 {
		go l.cleanup()
	}

	return nil
}

func (l *Logger) cleanup() {
	if l.pruneDays == 0 {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -l.pruneDays)

	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".log") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(l.dir, name))
		}
	}
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

func getDate() string {
	return time.Now().Format("2006-01-02")
}
