package mail

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestConfigConfigured(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"empty", Config{}, false},
		{"host only", Config{Host: "smtp.example.com"}, false},
		{"from only", Config{From: "noreply@example.com"}, false},
		{"host and from", Config{Host: "smtp.example.com", From: "noreply@example.com"}, true},
	}

	for _, c := range cases {
		if got := c.cfg.Configured(); got != c.want {
			t.Errorf("%s: Configured() = %v, want %v", c.name, got, c.want)
		}
	}
}

// fakeSMTPServer accepts exactly one plaintext SMTP connection, speaks just
// enough of the protocol for net/smtp to complete a send, and records what
// it received so the test can assert on it.
type fakeSMTPServer struct {
	addr        string
	requireAuth bool

	gotMailFrom string
	gotRcptTo   string
	gotAuth     bool
	gotData     string
}

func startFakeSMTPServer(t *testing.T, requireAuth bool) *fakeSMTPServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &fakeSMTPServer{addr: ln.Addr().String(), requireAuth: requireAuth}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		srv.serve(conn)
	}()

	return srv
}

func (s *fakeSMTPServer) serve(conn net.Conn) {
	r := bufio.NewReader(conn)
	send := func(line string) { _, _ = fmt.Fprintf(conn, "%s\r\n", line) }

	send("220 fake.local ESMTP")

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			send("250-fake.local greets you")
			if s.requireAuth {
				send("250 AUTH PLAIN LOGIN")
			} else {
				send("250 OK")
			}
		case strings.HasPrefix(upper, "AUTH PLAIN"):
			s.gotAuth = true
			send("235 authenticated")
		case strings.HasPrefix(upper, "MAIL FROM:"):
			s.gotMailFrom = extractAngle(line)
			send("250 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			s.gotRcptTo = extractAngle(line)
			send("250 OK")
		case upper == "DATA":
			send("354 send it")
			var body strings.Builder
			for {
				dataLine, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
				body.WriteString(dataLine)
			}
			s.gotData = body.String()
			send("250 OK: queued")
		case upper == "QUIT":
			send("221 bye")
			return
		default:
			send("250 OK")
		}
	}
}

func extractAngle(line string) string {
	start := strings.Index(line, "<")
	end := strings.Index(line, ">")
	if start < 0 || end < 0 || end < start {
		return line
	}
	return line[start+1 : end]
}

func TestSMTPMailerSendPlaintext(t *testing.T) {
	srv := startFakeSMTPServer(t, false)
	host, portStr, _ := net.SplitHostPort(srv.addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	m := NewSMTPMailer(Config{Host: host, Port: port, From: "noreply@example.com", TLSMode: TLSNone})

	if err := m.Send("someone@example.com", "Test subject", "Test body\nsecond line"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	// Give the goroutine a moment to finish recording before we read its
	// fields; QUIT has already round-tripped by the time Send returns, so
	// this is a formality rather than a real race in practice.
	time.Sleep(50 * time.Millisecond)

	if srv.gotMailFrom != "noreply@example.com" {
		t.Errorf("MAIL FROM was %q, want noreply@example.com", srv.gotMailFrom)
	}
	if srv.gotRcptTo != "someone@example.com" {
		t.Errorf("RCPT TO was %q, want someone@example.com", srv.gotRcptTo)
	}
	if !strings.Contains(srv.gotData, "Subject: Test subject") {
		t.Errorf("message is missing the subject header: %q", srv.gotData)
	}
	if !strings.Contains(srv.gotData, "Test body") || !strings.Contains(srv.gotData, "second line") {
		t.Errorf("message is missing the body: %q", srv.gotData)
	}
}

func TestSMTPMailerSendsAuthWhenCredentialsAreSet(t *testing.T) {
	srv := startFakeSMTPServer(t, true)
	host, portStr, _ := net.SplitHostPort(srv.addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	// PlainAuth over a plaintext connection is only permitted to localhost --
	// which this is, since the fake server listens on 127.0.0.1 -- so this
	// exercises the real auth path rather than net/smtp's own safety guard.
	m := NewSMTPMailer(Config{
		Host: host, Port: port, From: "noreply@example.com",
		Username: "someuser", Password: "somepass", TLSMode: TLSNone,
	})

	if err := m.Send("someone@example.com", "Subject", "Body"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if !srv.gotAuth {
		t.Error("the server never saw an AUTH command, though credentials were configured")
	}
}

func TestSMTPMailerFailsWithoutConfiguration(t *testing.T) {
	m := NewSMTPMailer(Config{})
	if err := m.Send("someone@example.com", "Subject", "Body"); err == nil {
		t.Fatal("Send should refuse to run against an unconfigured Config")
	}
}

func TestNoopMailerCallsTheLogFunctionAndDoesNotError(t *testing.T) {
	var logged []string
	m := NoopMailer{Log: func(to, subject, _ string) {
		logged = append(logged, to+"|"+subject)
	}}

	if err := m.Send("someone@example.com", "Subject", "Body"); err != nil {
		t.Fatalf("NoopMailer.Send should never error: %v", err)
	}
	if len(logged) != 1 || logged[0] != "someone@example.com|Subject" {
		t.Errorf("got %v, want exactly one matching log entry", logged)
	}
}

func TestNoopMailerToleratesNoLogFunction(t *testing.T) {
	m := NoopMailer{}
	if err := m.Send("someone@example.com", "Subject", "Body"); err != nil {
		t.Fatalf("NoopMailer.Send should never error even with no Log set: %v", err)
	}
}
