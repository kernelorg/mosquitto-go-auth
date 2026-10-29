package backends

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"layeh.com/radius"
	"layeh.com/radius/rfc2869"
)

// radiusTransport sends an encoded RADIUS request and returns the raw response.
// Implementations must only return responses whose identifier matches the request.
type radiusTransport interface {
	Exchange(ctx context.Context, wire []byte) ([]byte, error)
	Addr() string
	Close() error
}

// radiusUDPTransport is the classic RADIUS over UDP transport (RFC 2865).
// A fresh socket is used for every exchange so that stray or late responses of
// previous requests can never be mixed up with the current one.
type radiusUDPTransport struct {
	address string
}

func newRadiusUDPTransport(address string) *radiusUDPTransport {
	return &radiusUDPTransport{address: address}
}

func (t *radiusUDPTransport) Addr() string { return t.address }

func (t *radiusUDPTransport) Close() error { return nil }

func (t *radiusUDPTransport) Exchange(ctx context.Context, wire []byte) ([]byte, error) {
	var dialer net.Dialer

	conn, err := dialer.DialContext(ctx, "udp", t.address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}

	buf := make([]byte, radius.MaxPacketLength)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}

		// Ignore datagrams that are too short or belong to another request.
		if n < 20 || buf[1] != wire[1] {
			continue
		}

		length := int(binary.BigEndian.Uint16(buf[2:4]))
		if length < 20 || length > n {
			continue
		}

		out := make([]byte, length)
		copy(out, buf[:length])

		return out, nil
	}
}

// radiusRadSecTransport implements RADIUS over TLS (RadSec, RFC 6614).
// A single TLS connection is kept open and reused; it is re-established
// transparently when the server closes it.
type radiusRadSecTransport struct {
	address   string
	tlsConfig *tls.Config

	mu   sync.Mutex
	conn net.Conn
}

func newRadiusRadSecTransport(address string, tlsConfig *tls.Config) *radiusRadSecTransport {
	return &radiusRadSecTransport{address: address, tlsConfig: tlsConfig}
}

func (t *radiusRadSecTransport) Addr() string { return t.address }

func (t *radiusRadSecTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		err := t.conn.Close()
		t.conn = nil

		return err
	}

	return nil
}

func (t *radiusRadSecTransport) Exchange(ctx context.Context, wire []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	reused := t.conn != nil

	if err := t.dialLocked(ctx); err != nil {
		return nil, err
	}

	resp, err := t.roundTripLocked(ctx, wire)
	if err == nil {
		return resp, nil
	}

	t.closeLocked()

	// A reused connection may have been closed by the server while idle:
	// retry once on a fresh connection before giving up.
	if !reused {
		return nil, err
	}

	if err := t.dialLocked(ctx); err != nil {
		return nil, err
	}

	resp, err = t.roundTripLocked(ctx, wire)
	if err != nil {
		t.closeLocked()

		return nil, err
	}

	return resp, nil
}

func (t *radiusRadSecTransport) dialLocked(ctx context.Context) error {
	if t.conn != nil {
		return nil
	}

	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: t.tlsConfig}

	conn, err := dialer.DialContext(ctx, "tcp", t.address)
	if err != nil {
		return err
	}

	t.conn = conn

	return nil
}

func (t *radiusRadSecTransport) closeLocked() {
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}
}

func (t *radiusRadSecTransport) roundTripLocked(ctx context.Context, wire []byte) ([]byte, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := t.conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}

	if _, err := t.conn.Write(wire); err != nil {
		return nil, err
	}

	return radiusReadStreamPacket(t.conn, wire[1])
}

// radiusReadStreamPacket reads exactly one RADIUS packet from a stream
// connection, using the Length field of the header to frame it.
func radiusReadStreamPacket(r io.Reader, wantIdentifier byte) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < 20 || length > radius.MaxPacketLength {
		return nil, fmt.Errorf("radius: invalid packet length %d on stream", length)
	}

	buf := make([]byte, length)
	copy(buf, header)

	if _, err := io.ReadFull(r, buf[4:]); err != nil {
		return nil, err
	}

	if buf[1] != wantIdentifier {
		return nil, errors.New("radius: response identifier mismatch on stream")
	}

	return buf, nil
}

// newRadSecTLSConfig builds the TLS configuration for a RadSec connection.
func newRadSecTLSConfig(caFile, certFile, keyFile, serverName string, verify bool) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: !verify,
	}

	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("radius: read tls ca: %w", err)
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("radius: no certificates found in %s", caFile)
		}

		cfg.RootCAs = pool
	}

	if certFile != "" || keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("radius: load tls client certificate: %w", err)
		}

		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// radiusFindAttribute returns the offset of the first attribute of the given
// type inside an encoded packet, or false when it is absent or the packet is
// malformed.
func radiusFindAttribute(wire []byte, typ byte) (int, bool) {
	if len(wire) < 20 {
		return 0, false
	}

	length := int(binary.BigEndian.Uint16(wire[2:4]))
	if length > len(wire) {
		length = len(wire)
	}

	for off := 20; off+2 <= length; {
		attrLen := int(wire[off+1])
		if attrLen < 2 || off+attrLen > length {
			return 0, false
		}

		if wire[off] == typ {
			return off, true
		}

		off += attrLen
	}

	return 0, false
}

// radiusEncodeRequest encodes an Access-Request and signs it with a
// Message-Authenticator (RFC 2869 §5.14, mandatory since CVE-2024-3596).
func radiusEncodeRequest(p *radius.Packet) ([]byte, error) {
	if err := rfc2869.MessageAuthenticator_Set(p, make([]byte, 16)); err != nil {
		return nil, err
	}

	wire, err := p.Encode()
	if err != nil {
		return nil, err
	}

	off, ok := radiusFindAttribute(wire, byte(rfc2869.MessageAuthenticator_Type))
	if !ok || wire[off+1] != 18 {
		return nil, errors.New("radius: message-authenticator attribute missing after encoding")
	}

	mac := hmac.New(md5.New, p.Secret)
	mac.Write(wire)
	copy(wire[off+2:off+18], mac.Sum(nil))

	return wire, nil
}

// radiusVerifyMessageAuthenticator validates the Message-Authenticator of a
// response. requestAuthenticator is the authenticator of the matching request.
// It returns whether the attribute is present and whether it is valid.
func radiusVerifyMessageAuthenticator(wire, requestAuthenticator, secret []byte) (present bool, valid bool) {
	off, ok := radiusFindAttribute(wire, byte(rfc2869.MessageAuthenticator_Type))
	if !ok || wire[off+1] != 18 {
		return false, false
	}

	tmp := make([]byte, len(wire))
	copy(tmp, wire)
	copy(tmp[4:20], requestAuthenticator)

	for i := off + 2; i < off+18; i++ {
		tmp[i] = 0
	}

	mac := hmac.New(md5.New, secret)
	mac.Write(tmp)

	return true, hmac.Equal(mac.Sum(nil), wire[off+2:off+18])
}
