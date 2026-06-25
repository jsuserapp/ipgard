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

type searchRoot struct {
	root   string
	source string
	local  bool // local/test dirs: accept any .log file
}

var systemRoots = []searchRoot{
	{"/var/log/apache2", "apache", false},
	{"/var/log/httpd", "apache", false},
	{"/var/log/nginx", "nginx", false},
	{"/usr/local/nginx/logs", "nginx", false},
	{"/usr/local/apache2/logs", "apache", false},
	{"/opt/homebrew/var/log/httpd", "apache", false},
	{"/opt/homebrew/var/log/nginx", "nginx", false},
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

	roots := append(systemRoots, localRoots()...)

	for _, root := range roots {
		if _, err := os.Stat(root.root); err != nil {
			continue
		}
		if !root.local {
			for _, name := range nameHints {
				add(filepath.Join(root.root, name), root.source)
			}
		}
		_ = filepath.WalkDir(root.root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			base := strings.ToLower(d.Name())
			if root.local {
				if strings.HasSuffix(base, ".log") {
					add(path, root.source)
				}
				return nil
			}
			if strings.Contains(base, "access") && strings.HasSuffix(base, ".log") {
				add(path, root.source)
			}
			return nil
		})
	}
	return out
}

func localRoots() []searchRoot {
	seen := map[string]bool{}
	var roots []searchRoot

	addDir := func(dir string) {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return
		}
		if seen[abs] {
			return
		}
		if info, err := os.Stat(abs); err != nil || !info.IsDir() {
			return
		}
		seen[abs] = true
		roots = append(roots, searchRoot{root: abs, source: "local", local: true})
	}

	for _, base := range baseDirs() {
		for _, rel := range []string{"testdata", "testdata/logs", "testdata\\logs"} {
			addDir(filepath.Join(base, rel))
		}
	}
	return roots
}

func baseDirs() []string {
	dirs := make([]string, 0, 2)
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Dir(exe))
	}
	return dirs
}
