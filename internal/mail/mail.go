// Package mail sends the one kind of message this server ever sends: a
// recovery code, to prove the requester controls the account's email
// before handing back anything an attacker could use.
//
// Deliberately generic SMTP rather than a provider's HTTP API. Every
// transactional-email provider worth using speaks SMTP even when they'd
// rather sell you their API, and a self-hoster running their own mail
// server, or Postfix relaying through their ISP, has no API to speak to at
// all. One client that works everywhere beats a plugin per provider.
package mail

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Mailer sends a plain-text message. The interface exists so the API layer
// can be tested against a fake without a real SMTP server, and so an
// unconfigured server can run with a no-op implementation instead of
// refusing to start.
type Mailer interface {
	Send(to, subject, body string) error
}

// TLSMode says how the connection to the SMTP server is secured.
type TLSMode string

const (
	// TLSImplicit dials straight into TLS -- the shape port 465 expects.
	TLSImplicit TLSMode = "tls"
	// TLSStartTLS dials plain and upgrades with STARTTLS -- port 587's shape,
	// and the most common choice for a transactional-mail provider.
	TLSStartTLS TLSMode = "starttls"
	// TLSNone sends over an unencrypted connection. Only ever appropriate
	// for a mail relay on localhost or a private network; SMTPMailer
	// refuses to send authenticated credentials over it.
	TLSNone TLSMode = "none"
)

type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLSMode  TLSMode
	// InsecureSkipVerify exists for a self-signed relay on a private
	// network in development. It is never appropriate against a real
	// provider, and there is deliberately no environment-variable shortcut
	// that flips it on by accident.
	InsecureSkipVerify bool
}

func (c Config) addr() string { return fmt.Sprintf("%s:%d", c.Host, c.Port) }

// Configured reports whether enough is set to attempt sending at all.
func (c Config) Configured() bool { return c.Host != "" && c.From != "" }

type SMTPMailer struct {
	cfg Config
}

func NewSMTPMailer(cfg Config) *SMTPMailer {
	return &SMTPMailer{cfg: cfg}
}

/**
 * The three shapes an SMTP connection comes in, and this is the one place
 * that has to know all three:
 *
 *   implicit TLS   dial straight into crypto/tls, then speak SMTP inside it
 *   STARTTLS       dial plain, issue STARTTLS, upgrade the same connection
 *   none           dial plain and stay there
 *
 * net/smtp's own SendMail helper only covers the STARTTLS-or-nothing case
 * and can't do implicit TLS at all, which is why this dials by hand instead
 * of using it.
 */
func (m *SMTPMailer) Send(to, subject, body string) error {
	if !m.cfg.Configured() {
		return fmt.Errorf("mail: no SMTP server configured")
	}

	client, err := m.dial()
	if err != nil {
		return fmt.Errorf("mail: connect: %w", err)
	}
	defer func() { _ = client.Close() }()

	if m.cfg.TLSMode == TLSStartTLS {
		tlsConfig := &tls.Config{ServerName: m.cfg.Host, InsecureSkipVerify: m.cfg.InsecureSkipVerify} //nolint:gosec // opt-in, documented on Config
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("mail: starttls: %w", err)
		}
	}

	if m.cfg.Username != "" {
		// net/smtp refuses PLAIN auth unless the connection is TLS or to
		// localhost, which is exactly the guard rail we want here too --
		// a credential should never go out over a connection that isn't
		// at least as secure as the credential itself.
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("mail: authenticate: %w", err)
		}
	}

	if err := client.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("mail: MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("mail: RCPT TO: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("mail: DATA: %w", err)
	}
	if _, err := w.Write([]byte(message(m.cfg.From, to, subject, body))); err != nil {
		_ = w.Close()
		return fmt.Errorf("mail: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("mail: close body: %w", err)
	}

	return client.Quit()
}

func (m *SMTPMailer) dial() (*smtp.Client, error) {
	if m.cfg.TLSMode == TLSImplicit {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 15 * time.Second},
			"tcp", m.cfg.addr(),
			&tls.Config{ServerName: m.cfg.Host, InsecureSkipVerify: m.cfg.InsecureSkipVerify}, //nolint:gosec // opt-in, documented on Config
		)
		if err != nil {
			return nil, err
		}
		return smtp.NewClient(conn, m.cfg.Host)
	}

	conn, err := net.DialTimeout("tcp", m.cfg.addr(), 15*time.Second)
	if err != nil {
		return nil, err
	}
	return smtp.NewClient(conn, m.cfg.Host)
}

// message builds a minimal RFC 5322 message. No HTML part: this server
// sends exactly one kind of email, a short code someone needs to read and
// paste, and plain text renders that identically everywhere.
func message(from, to, subject, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	b.WriteString("\r\n")
	return b.String()
}

// NoopMailer logs instead of sending, so a server with no SMTP configured
// still starts and runs -- email-based recovery just reports itself
// unavailable rather than the whole process refusing to boot over an
// optional feature.
type NoopMailer struct {
	Log func(to, subject, body string)
}

func (m NoopMailer) Send(to, subject, body string) error {
	if m.Log != nil {
		m.Log(to, subject, body)
	}
	return nil
}
