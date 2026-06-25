package logdiscover

import (
	"os"
	"path/filepath"
	"strings"
)

type LogCandidate struct {
	Path   string `json:"path"`
	Source string `json:"source"`
	Size   int64  `json:"size"`
}

var searchRoots = []struct {
	root   string
	source string
}{
	{"/var/log/apache2", "apache"},
	{"/var/log/httpd", "apache"},
	{"/var/log/nginx", "nginx"},
	{"/usr/local/nginx/logs", "nginx"},
	{"/usr/local/apache2/logs", "apache"},
	{"/opt/homebrew/var/log/httpd", "apache"},
	{"/opt/homebrew/var/log/nginx", "nginx"},
}

var nameHints = []string{
	"access.log",
	"access_log",
	"access.log.1",
	"ssl_access.log",
	"ssl-access.log",
}

func Discover() []LogCandidate {
	seen := map[string]bool{}
	var out []LogCandidate

	add := func(path, source string) {
		if seen[path] {
			return
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return
		}
		seen[path] = true
		out = append(out, LogCandidate{
			Path:   path,
			Source: source,
			Size:   info.Size(),
		})
	}

	for _, root := range searchRoots {
		if _, err := os.Stat(root.root); err != nil {
			continue
		}
		for _, name := range nameHints {
			add(filepath.Join(root.root, name), root.source)
		}
		_ = filepath.WalkDir(root.root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			base := strings.ToLower(d.Name())
			if strings.Contains(base, "access") && strings.HasSuffix(base, ".log") {
				add(path, root.source)
			}
			return nil
		})
	}
	return out
}
