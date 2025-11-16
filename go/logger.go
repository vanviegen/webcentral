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

const LogRetentionDays = 21

type Logger struct {
	dir       string
	file      *os.File
	mu        sync.Mutex
	currentDate string
	uid       int
	gid       int
}

func NewLogger(dir string, uid, gid int) (*Logger, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	logger := &Logger{
		dir: dir,
		uid: uid,
		gid: gid,
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

	timestamp := time.Now().Format("2006-01-02T15:04:05.000Z07:00")

	var output string
	if topic != "" {
		output = fmt.Sprintf("%s %s\n", timestamp, topic)
	} else {
		output = fmt.Sprintf("%s\n", timestamp)
	}

	// Handle multi-line messages with indentation
	lines := strings.Split(message, "\n")
	for i, line := range lines {
		if i == 0 && topic != "" {
			output += fmt.Sprintf("  %s\n", line)
		} else if line != "" {
			output += fmt.Sprintf("  %s\n", line)
		} else if i < len(lines)-1 {
			output += "\n"
		}
	}

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

	// Clean up old log files
	go l.cleanup()

	return nil
}

func (l *Logger) cleanup() {
	cutoff := time.Now().AddDate(0, 0, -LogRetentionDays)

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
