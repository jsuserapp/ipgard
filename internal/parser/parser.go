package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// AccessEntry is a normalized access log line.
type AccessEntry struct {
	IP        string
	Method    string
	Path      string
	Status    int
	Bytes     int64
	Referer   string
	UserAgent string
	Time      time.Time
}

var (
	// Apache/Nginx combined log format:
	// 127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.0" 200 2326 "..." "..."
	combinedRe = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d+)\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?`)

	// Common log format (no referer/user-agent):
	// 127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.0" 200 2326
	commonRe = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]*"\s+(\d+)\s+(\S+)`)

	logTimeLayouts = []string{
		"02/Jan/2006:15:04:05 -0700",
		"02/Jan/2006:15:04:05 -0700",
	}
)

func ParseLine(line, format string) (*AccessEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	switch format {
	case "common":
		return parseCommon(line)
	case "combined", "nginx", "apache":
		return parseCombined(line)
	default:
		if e, err := parseCombined(line); err == nil && e != nil {
			return e, nil
		}
		return parseCommon(line)
	}
}

func parseCombined(line string) (*AccessEntry, error) {
	m := combinedRe.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	return buildEntry(m[1], m[2], m[3], m[4], m[5], m[6], optionalField(m, 7), optionalField(m, 8))
}

func parseCommon(line string) (*AccessEntry, error) {
	m := commonRe.FindStringSubmatch(line)
	if m == nil {
		return nil, nil
	}
	return buildEntry(m[1], m[2], m[3], m[4], m[5], m[6], "", "")
}

func optionalField(m []string, idx int) string {
	if len(m) > idx {
		return m[idx]
	}
	return ""
}

func buildEntry(ip, timeStr, method, path, statusStr, bytesStr, referer, ua string) (*AccessEntry, error) {
	status, _ := strconv.Atoi(statusStr)
	var bytes int64
	if bytesStr != "-" {
		bytes, _ = strconv.ParseInt(bytesStr, 10, 64)
	}

	t, err := parseLogTime(timeStr)
	if err != nil {
		t = time.Now()
	}

	return &AccessEntry{
		IP:        ip,
		Method:    method,
		Path:      path,
		Status:    status,
		Bytes:     bytes,
		Referer:   referer,
		UserAgent: ua,
		Time:      t,
	}, nil
}

func parseLogTime(s string) (time.Time, error) {
	for _, layout := range logTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, strconv.ErrSyntax
}

func DetectFormat(sample string) string {
	sample = strings.TrimSpace(sample)
	if combinedRe.MatchString(sample) {
		return "combined"
	}
	if commonRe.MatchString(sample) {
		return "common"
	}
	return "auto"
}
