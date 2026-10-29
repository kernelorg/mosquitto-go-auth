package backends

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"
	"layeh.com/radius/vendors/mikrotik"
)

const radiusTestSecret = "testing123"

// radiusTestHandler builds a response for a request, or returns nil to drop it.
type radiusTestHandler func(req *radius.Packet) *radius.Packet

// radiusTestServer is a minimal RADIUS/UDP server used by the tests.
type radiusTestServer struct {
	t               *testing.T
	conn            net.PacketConn
	secret          []byte
	handler         radiusTestHandler
	signResponses   bool
	corruptMA       bool
	verifyRequestMA bool
	requests        atomic.Int32
	badRequests     atomic.Int32
}

// newRadiusTestServer starts a server; options are applied before the serving
// goroutine starts so the test never races with it.
func newRadiusTestServer(t *testing.T, secret string, handler radiusTestHandler, options ...func(*radiusTestServer)) *radiusTestServer {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	s := &radiusTestServer{
		t:               t,
		conn:            conn,
		secret:          []byte(secret),
		handler:         handler,
		signResponses:   true,
		verifyRequestMA: true,
	}

	for _, option := range options {
		option(s)
	}

	go s.serve()

	t.Cleanup(func() { conn.Close() })

	return s
}

func (s *radiusTestServer) addr() string {
	return s.conn.LocalAddr().String()
}

func (s *radiusTestServer) serve() {
	buf := make([]byte, radius.MaxPacketLength)

	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}

		s.requests.Add(1)

		wire := make([]byte, n)
		copy(wire, buf[:n])

		req, err := radius.Parse(wire, s.secret)
		if err != nil {
			s.badRequests.Add(1)

			continue
		}

		if s.verifyRequestMA {
			if present, valid := radiusVerifyMessageAuthenticator(wire, wire[4:20], s.secret); !present || !valid {
				s.badRequests.Add(1)

				continue
			}
		}

		resp := s.handler(req)
		if resp == nil {
			continue
		}

		out, err := radiusEncodeTestResponse(resp, req.Authenticator, s.secret, s.signResponses, s.corruptMA)
		if err != nil {
			s.t.Logf("encode response: %s", err)

			continue
		}

		s.conn.WriteTo(out, addr)
	}
}

// radiusEncodeTestResponse encodes a response the way a real server does:
// Message-Authenticator first (computed with the request authenticator in the
// header), then the Response Authenticator over the final packet.
func radiusEncodeTestResponse(resp *radius.Packet, requestAuth [16]byte, secret []byte, sign, corrupt bool) ([]byte, error) {
	resp.Secret = secret
	resp.Authenticator = requestAuth

	if sign {
		if err := rfc2869.MessageAuthenticator_Set(resp, make([]byte, 16)); err != nil {
			return nil, err
		}
	}

	wire, err := resp.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if sign {
		off, ok := radiusFindAttribute(wire, byte(rfc2869.MessageAuthenticator_Type))
		if !ok {
			panic("message-authenticator missing")
		}

		mac := hmac.New(md5.New, secret)
		mac.Write(wire)
		copy(wire[off+2:off+18], mac.Sum(nil))

		if corrupt {
			wire[off+2] ^= 0xff
		}
	}

	h := md5.New()
	h.Write(wire[:4])
	h.Write(requestAuth[:])
	h.Write(wire[20:])
	h.Write(secret)
	copy(wire[4:20], h.Sum(nil))

	return wire, nil
}

// radiusAcceptPAP accepts the given credentials and decorates the Access-Accept.
func radiusAcceptPAP(username, password string, decorate func(resp *radius.Packet)) radiusTestHandler {
	return func(req *radius.Packet) *radius.Packet {
		if rfc2865.UserName_GetString(req) != username || rfc2865.UserPassword_GetString(req) != password {
			resp := req.Response(radius.CodeAccessReject)
			rfc2865.ReplyMessage_SetString(resp, "bad credentials")

			return resp
		}

		resp := req.Response(radius.CodeAccessAccept)
		if decorate != nil {
			decorate(resp)
		}

		return resp
	}
}

func radiusDecorateAlice(resp *radius.Packet) {
	rfc2865.FilterID_AddString(resp, "readwrite:sensors/%u/#")
	rfc2865.FilterID_AddString(resp, "read:status/#")
	rfc2865.FilterID_AddString(resp, "deny:sensors/%u/private")
	rfc2865.FilterID_AddString(resp, "garbage without separator")
	mikrotik.MikrotikGroup_AddString(resp, "sensors")
}

func radiusTestOpts(server string, extra map[string]string) map[string]string {
	opts := map[string]string{
		"radius_servers":    server,
		"radius_secret":     radiusTestSecret,
		"radius_timeout_ms": "300",
		"radius_retries":    "0",
	}

	for k, v := range extra {
		opts[k] = v
	}

	return opts
}

func TestRADIUSConfig(t *testing.T) {
	_, err := NewRADIUS(map[string]string{}, log.ErrorLevel)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "radius_servers")
	assert.Contains(t, err.Error(), "radius_secret")

	r, err := NewRADIUS(map[string]string{"radius_servers": "10.0.0.1, 10.0.0.2:1645", "radius_secret": "s"}, log.ErrorLevel)
	require.NoError(t, err)
	defer r.Halt()
	assert.Equal(t, []string{"10.0.0.1:1812", "10.0.0.2:1645"}, r.Servers)
	assert.Equal(t, radiusProtocolUDP, r.Protocol)
	assert.Equal(t, radiusDefaultTimeout, r.Timeout)
	assert.Equal(t, radiusDefaultRetries, r.Retries)
	assert.Equal(t, "mosquitto", r.NASIdentifier)
	assert.Equal(t, radiusAuthPAP, r.AuthProtocol)
	assert.Equal(t, radiusDefaultCacheTTL, r.CacheTTL)
	assert.Equal(t, uint32(radiusMikrotikVendorID), r.SuperuserAttr.vendorID)
	assert.Equal(t, byte(3), r.SuperuserAttr.typ)
	assert.Equal(t, "mqtt-superuser", r.SuperuserValue)
	assert.Equal(t, byte(11), r.AclAttr.typ)
	assert.False(t, r.AclDefaultAllow)

	r, err = NewRADIUS(map[string]string{
		"radius_servers":                       "10.0.0.1",
		"radius_protocol":                      "radsec",
		"radius_acl_default":                   "allow",
		"radius_acl_attr":                      "vsa:9:1",
		"radius_superuser_attr":                "Class",
		"radius_group_attr":                    "",
		"radius_nas_ip":                        "192.0.2.10",
		"radius_auth_protocol":                 "chap",
		"radius_attr_cache_seconds":            "60",
		"radius_require_message_authenticator": "true",
	}, log.ErrorLevel)
	require.NoError(t, err)
	defer r.Halt()
	assert.Equal(t, []string{"10.0.0.1:2083"}, r.Servers)
	assert.Equal(t, []byte(radiusRadSecSecret), r.Secret)
	assert.True(t, r.AclDefaultAllow)
	assert.Equal(t, radiusAttrRef{name: "vsa:9:1", vendorID: 9, typ: 1}, r.AclAttr)
	assert.Equal(t, byte(25), r.SuperuserAttr.typ)
	assert.False(t, r.GroupAttr.valid())
	assert.Equal(t, net.IPv4(192, 0, 2, 10).To4(), r.NASIPAddress)
	assert.Equal(t, radiusAuthCHAP, r.AuthProtocol)
	assert.Equal(t, 60*time.Second, r.CacheTTL)
	assert.True(t, r.RequireMessageAuthenticator)

	for _, bad := range []map[string]string{
		{"radius_protocol": "tcp"},
		{"radius_auth_protocol": "mschap"},
		{"radius_acl_default": "maybe"},
		{"radius_acl_attr": "No-Such-Attribute"},
		{"radius_acl_attr": "vsa:1"},
		{"radius_timeout_ms": "0"},
		{"radius_retries": "-1"},
		{"radius_nas_ip": "2001:db8::1"},
		{"radius_attr_cache_seconds": "x"},
		{"radius_acl_file": "/nonexistent/acl"},
	} {
		opts := radiusTestOpts("127.0.0.1:1812", bad)
		_, err := NewRADIUS(opts, log.ErrorLevel)
		assert.Error(t, err, "options %v should fail", bad)
	}
}

func TestRADIUSAttrRefValues(t *testing.T) {
	p := radius.New(radius.CodeAccessAccept, []byte("x"))
	rfc2865.FilterID_AddString(p, "one")
	rfc2865.FilterID_AddString(p, "two")
	mikrotik.MikrotikGroup_AddString(p, "g1")
	mikrotik.MikrotikRealm_AddString(p, "realm")

	// A single VSA carrying two sub-attributes.
	sub := append([]byte{3, 4, 'g', '2'}, []byte{9, 4, 'r', '2'}...)
	vsa, err := radius.NewVendorSpecific(radiusMikrotikVendorID, sub)
	require.NoError(t, err)
	p.Add(rfc2865.VendorSpecific_Type, vsa)

	filterID, _ := parseRadiusAttrRef("Filter-Id")
	group, _ := parseRadiusAttrRef("Mikrotik-Group")
	realm, _ := parseRadiusAttrRef("vsa:14988:9")
	other, _ := parseRadiusAttrRef("vsa:9:1")

	assert.Equal(t, []string{"one", "two"}, filterID.values(p))
	assert.Equal(t, []string{"g1", "g2"}, group.values(p))
	assert.Equal(t, []string{"realm", "r2"}, realm.values(p))
	assert.Nil(t, other.values(p))
	assert.Nil(t, radiusAttrRef{}.values(p))
}

func TestRADIUSACLRules(t *testing.T) {
	rule, err := parseRadiusACLRule(" ReadWrite : sensors/%u/# ")
	require.NoError(t, err)
	assert.Equal(t, radiusACLRule{topic: "sensors/%u/#", acc: MOSQ_ACL_READWRITE}, rule)

	rule, err = parseRadiusACLRule("4:a/b")
	require.NoError(t, err)
	assert.Equal(t, int32(MOSQ_ACL_SUBSCRIBE), rule.acc)

	rule, err = parseRadiusACLRule("deny:a:b")
	require.NoError(t, err)
	assert.Equal(t, "a:b", rule.topic)

	for _, bad := range []string{"", "nocolon", "x:a/b", "read:", "5:a"} {
		_, err := parseRadiusACLRule(bad)
		assert.Error(t, err, bad)
	}

	rules := []radiusACLRule{
		{topic: "sensors/%u/#", acc: MOSQ_ACL_READWRITE},
		{topic: "status/#", acc: MOSQ_ACL_READ},
		{topic: "cmd/%c", acc: MOSQ_ACL_WRITE},
		{topic: "sensors/%u/private", acc: MOSQ_ACL_DENY},
		{topic: "subs/#", acc: MOSQ_ACL_SUBSCRIBE},
	}

	check := func(topic string, acc int32) bool {
		return radiusCheckACL(rules, "alice", "client1", topic, acc)
	}

	assert.True(t, check("sensors/alice/temp", MOSQ_ACL_WRITE))
	assert.True(t, check("sensors/alice/temp", MOSQ_ACL_READ))
	assert.True(t, check("sensors/alice/temp", MOSQ_ACL_SUBSCRIBE))
	assert.False(t, check("sensors/bob/temp", MOSQ_ACL_READ))
	assert.False(t, check("sensors/alice/private", MOSQ_ACL_READ))
	assert.False(t, check("sensors/alice/private", MOSQ_ACL_WRITE))
	assert.True(t, check("status/x", MOSQ_ACL_READ))
	assert.True(t, check("status/x", MOSQ_ACL_SUBSCRIBE))
	assert.False(t, check("status/x", MOSQ_ACL_WRITE))
	assert.True(t, check("cmd/client1", MOSQ_ACL_WRITE))
	assert.False(t, check("cmd/client1", MOSQ_ACL_READ))
	assert.False(t, check("cmd/client2", MOSQ_ACL_WRITE))
	assert.True(t, check("subs/x", MOSQ_ACL_SUBSCRIBE))
	assert.False(t, check("subs/x", MOSQ_ACL_READ))
	assert.False(t, check("#", MOSQ_ACL_SUBSCRIBE))
	assert.False(t, check("other", MOSQ_ACL_READ))
	assert.False(t, radiusCheckACL(nil, "alice", "c", "x", MOSQ_ACL_READ))
}

func TestRADIUSGroupACLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "groups.acl")

	require.NoError(t, os.WriteFile(path, []byte(`
# common rules
topic read status/#
group sensors
topic readwrite sensors/%u/#
pattern deny sensors/%u/private
# defaults to readwrite
topic cmd/%c
group admins
topic readwrite #
group empty
`), 0o600))

	g, err := newRadiusGroupACL(path)
	require.NoError(t, err)
	defer g.stop()

	assert.Equal(t, []radiusACLRule{{topic: "status/#", acc: MOSQ_ACL_READ}}, g.rulesFor(nil))
	assert.Equal(t, []radiusACLRule{
		{topic: "status/#", acc: MOSQ_ACL_READ},
		{topic: "sensors/%u/#", acc: MOSQ_ACL_READWRITE},
		{topic: "sensors/%u/private", acc: MOSQ_ACL_DENY},
		{topic: "cmd/%c", acc: MOSQ_ACL_READWRITE},
	}, g.rulesFor([]string{"sensors", "unknown"}))
	assert.Len(t, g.rulesFor([]string{"sensors", "admins"}), 5)
	assert.Len(t, g.rulesFor([]string{"empty"}), 1)

	require.NoError(t, os.WriteFile(path, []byte("user alice\n"), 0o600))
	_, err = newRadiusGroupACL(path)
	assert.Error(t, err)

	require.NoError(t, os.WriteFile(path, []byte("group\n"), 0o600))
	_, err = newRadiusGroupACL(path)
	assert.Error(t, err)
}

func TestRADIUSPAPAuth(t *testing.T) {
	server := newRadiusTestServer(t, radiusTestSecret, radiusAcceptPAP("alice", "secret", func(resp *radius.Packet) {
		radiusDecorateAlice(resp)
		mikrotik.MikrotikGroup_AddString(resp, "mqtt-superuser")
	}))

	dir := t.TempDir()
	aclFile := filepath.Join(dir, "groups.acl")
	require.NoError(t, os.WriteFile(aclFile, []byte("topic read broadcast/#\ngroup sensors\ntopic write telemetry/%c\n"), 0o600))

	r, err := NewRADIUS(radiusTestOpts(server.addr(), map[string]string{"radius_acl_file": aclFile}), log.DebugLevel)
	require.NoError(t, err)
	defer r.Halt()

	ok, err := r.GetUser("alice", "wrong", "client1")
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = r.GetSuperuser("alice")
	require.NoError(t, err)
	assert.False(t, ok, "rejected user must not be cached")

	ok, err = r.CheckAcl("alice", "sensors/alice/temp", "client1", MOSQ_ACL_WRITE)
	require.NoError(t, err)
	assert.False(t, ok, "default is deny without cached attributes")

	ok, err = r.GetUser("", "secret", "client1")
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = r.GetUser("alice", "secret", "client1")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = r.GetSuperuser("alice")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = r.GetSuperuser("bob")
	require.NoError(t, err)
	assert.False(t, ok)

	// Rules from Filter-Id.
	for _, c := range []struct {
		topic  string
		acc    int32
		expect bool
	}{
		{"sensors/alice/temp", MOSQ_ACL_WRITE, true},
		{"sensors/alice/temp", MOSQ_ACL_READ, true},
		{"sensors/alice/private", MOSQ_ACL_READ, false},
		{"sensors/bob/temp", MOSQ_ACL_WRITE, false},
		{"status/x", MOSQ_ACL_READ, true},
		{"status/x", MOSQ_ACL_WRITE, false},
		// Rules from the group file: common and group "sensors".
		{"broadcast/x", MOSQ_ACL_READ, true},
		{"telemetry/client1", MOSQ_ACL_WRITE, true},
		{"telemetry/client2", MOSQ_ACL_WRITE, false},
	} {
		ok, err := r.CheckAcl("alice", c.topic, "client1", c.acc)
		require.NoError(t, err)
		assert.Equal(t, c.expect, ok, "%s acc %d", c.topic, c.acc)
	}

	assert.Equal(t, int32(0), server.badRequests.Load(), "every request must carry a valid Message-Authenticator")

	// Attributes are not touched by a later failed login for the same user.
	ok, err = r.GetUser("alice", "wrong", "client1")
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = r.GetSuperuser("alice")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestRADIUSACLDefaultAllow(t *testing.T) {
	server := newRadiusTestServer(t, radiusTestSecret, radiusAcceptPAP("alice", "secret", nil))

	r, err := NewRADIUS(radiusTestOpts(server.addr(), map[string]string{"radius_acl_default": "allow"}), log.ErrorLevel)
	require.NoError(t, err)
	defer r.Halt()

	ok, err := r.CheckAcl("nobody", "any/topic", "c", MOSQ_ACL_WRITE)
	require.NoError(t, err)
	assert.True(t, ok, "unknown user falls back to the default")

	ok, err = r.GetUser("alice", "secret", "c")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = r.CheckAcl("alice", "any/topic", "c", MOSQ_ACL_WRITE)
	require.NoError(t, err)
	assert.True(t, ok, "user without rules falls back to the default")

	ok, err = r.GetSuperuser("alice")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestRADIUSCHAPAuth(t *testing.T) {
	server := newRadiusTestServer(t, radiusTestSecret, func(req *radius.Packet) *radius.Packet {
		chap := rfc2865.CHAPPassword_Get(req)
		challenge := rfc2865.CHAPChallenge_Get(req)

		if rfc2865.UserName_GetString(req) != "alice" || len(chap) != 17 || len(challenge) != 16 {
			return req.Response(radius.CodeAccessReject)
		}

		h := md5.New()
		h.Write(chap[:1])
		h.Write([]byte("secret"))
		h.Write(challenge)

		if !hmac.Equal(h.Sum(nil), chap[1:]) {
			return req.Response(radius.CodeAccessReject)
		}

		return req.Response(radius.CodeAccessAccept)
	})

	r, err := NewRADIUS(radiusTestOpts(server.addr(), map[string]string{"radius_auth_protocol": "chap"}), log.ErrorLevel)
	require.NoError(t, err)
	defer r.Halt()

	ok, err := r.GetUser("alice", "secret", "c")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = r.GetUser("alice", "nope", "c")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestRADIUSFailover(t *testing.T) {
	silent := newRadiusTestServer(t, radiusTestSecret, func(req *radius.Packet) *radius.Packet { return nil })
	alive := newRadiusTestServer(t, radiusTestSecret, radiusAcceptPAP("alice", "secret", nil))

	r, err := NewRADIUS(radiusTestOpts(silent.addr()+","+alive.addr(), map[string]string{
		"radius_retries":    "1",
		"radius_timeout_ms": "200",
	}), log.ErrorLevel)
	require.NoError(t, err)
	defer r.Halt()

	start := time.Now()
	ok, err := r.GetUser("alice", "secret", "c")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.GreaterOrEqual(t, time.Since(start), 400*time.Millisecond)
	assert.Equal(t, int32(2), silent.requests.Load(), "retries + 1 attempts on the silent server")
	assert.Equal(t, int32(1), alive.requests.Load())

	only, err := NewRADIUS(radiusTestOpts(silent.addr(), map[string]string{"radius_timeout_ms": "150"}), log.ErrorLevel)
	require.NoError(t, err)
	defer only.Halt()

	ok, err = only.GetUser("alice", "secret", "c")
	require.Error(t, err, "unreachable servers must surface an error, not a rejection")
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "no server answered")

	// Closed port: ICMP unreachable or timeout, either way an error.
	closed, err := NewRADIUS(radiusTestOpts("127.0.0.1:1", map[string]string{"radius_timeout_ms": "150"}), log.ErrorLevel)
	require.NoError(t, err)
	defer closed.Halt()

	_, err = closed.GetUser("alice", "secret", "c")
	require.Error(t, err)
}

func TestRADIUSMessageAuthenticator(t *testing.T) {
	unsigned := newRadiusTestServer(t, radiusTestSecret, radiusAcceptPAP("alice", "secret", nil),
		func(s *radiusTestServer) { s.signResponses = false })

	r, err := NewRADIUS(radiusTestOpts(unsigned.addr(), nil), log.ErrorLevel)
	require.NoError(t, err)
	defer r.Halt()

	ok, err := r.GetUser("alice", "secret", "c")
	require.NoError(t, err)
	assert.True(t, ok, "unsigned responses are accepted by default")

	strict, err := NewRADIUS(radiusTestOpts(unsigned.addr(), map[string]string{"radius_require_message_authenticator": "true"}), log.ErrorLevel)
	require.NoError(t, err)
	defer strict.Halt()

	ok, err = strict.GetUser("alice", "secret", "c")
	require.Error(t, err)
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "lacks message-authenticator")

	corrupt := newRadiusTestServer(t, radiusTestSecret, radiusAcceptPAP("alice", "secret", nil),
		func(s *radiusTestServer) { s.corruptMA = true })

	r2, err := NewRADIUS(radiusTestOpts(corrupt.addr(), nil), log.ErrorLevel)
	require.NoError(t, err)
	defer r2.Halt()

	ok, err = r2.GetUser("alice", "secret", "c")
	require.Error(t, err)
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "message-authenticator mismatch")

	// A server with another secret answers with an invalid Response Authenticator.
	other := newRadiusTestServer(t, "othersecret", radiusAcceptPAP("alice", "secret", nil),
		func(s *radiusTestServer) { s.verifyRequestMA = false; s.signResponses = false })

	r3, err := NewRADIUS(radiusTestOpts(other.addr(), nil), log.ErrorLevel)
	require.NoError(t, err)
	defer r3.Halt()

	ok, err = r3.GetUser("alice", "secret", "c")
	require.Error(t, err)
	assert.False(t, ok)
	assert.Contains(t, err.Error(), "response authenticator mismatch")
}

func TestRADIUSCacheExpiry(t *testing.T) {
	server := newRadiusTestServer(t, radiusTestSecret, radiusAcceptPAP("alice", "secret", func(resp *radius.Packet) {
		mikrotik.MikrotikGroup_AddString(resp, "mqtt-superuser")
		rfc2865.FilterID_AddString(resp, "readwrite:a/#")
	}))

	r, err := NewRADIUS(radiusTestOpts(server.addr(), map[string]string{"radius_attr_cache_seconds": "1"}), log.ErrorLevel)
	require.NoError(t, err)
	defer r.Halt()

	ok, err := r.GetUser("alice", "secret", "c")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, _ = r.GetSuperuser("alice")
	assert.True(t, ok)

	// Hits extend the lifetime.
	time.Sleep(600 * time.Millisecond)
	ok, _ = r.CheckAcl("alice", "a/b", "c", MOSQ_ACL_READ)
	assert.True(t, ok)
	time.Sleep(600 * time.Millisecond)
	ok, _ = r.GetSuperuser("alice")
	assert.True(t, ok)

	time.Sleep(1500 * time.Millisecond)

	ok, _ = r.GetSuperuser("alice")
	assert.False(t, ok, "attributes expire")
	ok, _ = r.CheckAcl("alice", "a/b", "c", MOSQ_ACL_READ)
	assert.False(t, ok)
}

// newRadSecTestServer starts a RADIUS over TLS server with a self-signed
// certificate and returns its address and the path of the CA file.
func newRadSecTestServer(t *testing.T, handler radiusTestHandler, closeAfterResponse bool) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "radsec-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, certPEM, 0o600))

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	secret := []byte(radiusRadSecSecret)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()

				for {
					header := make([]byte, 4)
					if _, err := io.ReadFull(conn, header); err != nil {
						return
					}

					length := int(binary.BigEndian.Uint16(header[2:4]))
					wire := make([]byte, length)
					copy(wire, header)

					if _, err := io.ReadFull(conn, wire[4:]); err != nil {
						return
					}

					req, err := radius.Parse(wire, secret)
					if err != nil {
						return
					}

					if present, valid := radiusVerifyMessageAuthenticator(wire, wire[4:20], secret); !present || !valid {
						return
					}

					resp := handler(req)
					if resp == nil {
						continue
					}

					out, err := radiusEncodeTestResponse(resp, req.Authenticator, secret, true, false)
					if err != nil {
						return
					}

					conn.Write(out)

					if closeAfterResponse {
						return
					}
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), caPath
}

func TestRADIUSRadSec(t *testing.T) {
	var requests atomic.Int32

	handler := func(req *radius.Packet) *radius.Packet {
		requests.Add(1)

		return radiusAcceptPAP("alice", "secret", radiusDecorateAlice)(req)
	}

	addr, caPath := newRadSecTestServer(t, handler, false)

	opts := map[string]string{
		"radius_servers":    addr,
		"radius_protocol":   "radsec",
		"radius_timeout_ms": "1000",
		"radius_retries":    "0",
		"radius_tls_ca":     caPath,
	}

	r, err := NewRADIUS(opts, log.DebugLevel)
	require.NoError(t, err)
	defer r.Halt()

	transport, isRadSec := r.transports[0].(*radiusRadSecTransport)
	require.True(t, isRadSec)

	for i := 0; i < 3; i++ {
		ok, err := r.GetUser("alice", "secret", "c")
		require.NoError(t, err)
		assert.True(t, ok)
	}

	ok, err := r.GetUser("alice", "wrong", "c")
	require.NoError(t, err)
	assert.False(t, ok)

	assert.Equal(t, int32(4), requests.Load())
	assert.NotNil(t, transport.conn, "the TLS connection is kept open between requests")

	ok, err = r.CheckAcl("alice", "sensors/alice/temp", "c", MOSQ_ACL_WRITE)
	require.NoError(t, err)
	assert.True(t, ok)

	// Verification against the system roots must fail for a self-signed server.
	untrusted, err := NewRADIUS(map[string]string{
		"radius_servers":    addr,
		"radius_protocol":   "radsec",
		"radius_timeout_ms": "1000",
	}, log.ErrorLevel)
	require.NoError(t, err)
	defer untrusted.Halt()

	ok, err = untrusted.GetUser("alice", "secret", "c")
	require.Error(t, err)
	assert.False(t, ok)

	// ... unless verification is disabled explicitly.
	insecure, err := NewRADIUS(map[string]string{
		"radius_servers":    addr,
		"radius_protocol":   "radsec",
		"radius_timeout_ms": "1000",
		"radius_tls_verify": "false",
	}, log.ErrorLevel)
	require.NoError(t, err)
	defer insecure.Halt()

	ok, err = insecure.GetUser("alice", "secret", "c")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestRADIUSRadSecReconnect(t *testing.T) {
	addr, caPath := newRadSecTestServer(t, radiusAcceptPAP("alice", "secret", nil), true)

	r, err := NewRADIUS(map[string]string{
		"radius_servers":    addr,
		"radius_protocol":   "radsec",
		"radius_timeout_ms": "1000",
		"radius_retries":    "0",
		"radius_tls_ca":     caPath,
	}, log.ErrorLevel)
	require.NoError(t, err)
	defer r.Halt()

	// The server closes the connection after every response; the transport
	// must notice the stale connection and reconnect without failing the check.
	for i := 0; i < 3; i++ {
		ok, err := r.GetUser("alice", "secret", "c")
		require.NoError(t, err, "attempt %d", i)
		assert.True(t, ok)

		time.Sleep(50 * time.Millisecond)
	}
}

func TestRADIUSBackendsIntegration(t *testing.T) {
	server := newRadiusTestServer(t, radiusTestSecret, radiusAcceptPAP("alice", "secret", radiusDecorateAlice))

	authOpts := radiusTestOpts(server.addr(), map[string]string{
		"backends":        "radius",
		"radius_register": "user, superuser, acl",
	})

	b, err := Initialize(authOpts, log.ErrorLevel, "2.0.0")
	require.NoError(t, err)
	defer b.Halt()

	ctx := context.Background()

	ok, err := b.AuthUnpwdCheck(ctx, "alice", "secret", "client1")
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = b.AuthUnpwdCheck(ctx, "alice", "bad", "client1")
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = b.AuthAclCheck(ctx, "client1", "alice", "sensors/alice/temp", MOSQ_ACL_WRITE)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = b.AuthAclCheck(ctx, "client1", "alice", "sensors/bob/temp", MOSQ_ACL_WRITE)
	require.NoError(t, err)
	assert.False(t, ok)

	ok, err = b.AuthAclCheck(ctx, "client1", "alice", "sensors/alice/private", MOSQ_ACL_READ)
	require.NoError(t, err)
	assert.False(t, ok)
}
