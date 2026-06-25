package parser

import "testing"

func TestParseCombined(t *testing.T) {
	line := `127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET /index.html HTTP/1.0" 200 2326 "http://example.com" "Mozilla/5.0"`
	entry, err := ParseLine(line, "combined")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil {
		t.Fatal("expected entry")
	}
	if entry.IP != "127.0.0.1" {
		t.Fatalf("ip: got %q", entry.IP)
	}
	if entry.Method != "GET" || entry.Path != "/index.html" {
		t.Fatalf("request: %s %s", entry.Method, entry.Path)
	}
	if entry.Status != 200 || entry.Bytes != 2326 {
		t.Fatalf("status/bytes: %d %d", entry.Status, entry.Bytes)
	}
}

func TestParseCommon(t *testing.T) {
	line := `192.168.1.2 - frank [10/Oct/2000:13:55:36 -0700] "POST /api HTTP/1.1" 404 123`
	entry, err := ParseLine(line, "common")
	if err != nil {
		t.Fatal(err)
	}
	if entry == nil || entry.IP != "192.168.1.2" {
		t.Fatalf("unexpected: %+v", entry)
	}
}
