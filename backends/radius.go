package backends

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

const (
	radiusProtocolUDP    = "udp"
	radiusProtocolRadSec = "radsec"

	radiusAuthPAP  = "pap"
	radiusAuthCHAP = "chap"

	radiusDefaultUDPPort    = "1812"
	radiusDefaultRadSecPort = "2083"

	// RFC 6614 §2.3: the shared secret over TLS is always "radsec".
	radiusRadSecSecret = "radsec"

	radiusMikrotikVendorID = 14988

	radiusDefaultTimeout  = 2000 * time.Millisecond
	radiusDefaultRetries  = 1
	radiusDefaultCacheTTL = 86400 * time.Second
)

// radiusAttrRef identifies a RADIUS attribute: a standard one (vendorID == 0)
// or a sub-attribute of a Vendor-Specific attribute.
type radiusAttrRef struct {
	name     string
	vendorID uint32
	typ      byte
}

var radiusKnownAttrs = map[string]radiusAttrRef{
	"user-name":                 {vendorID: 0, typ: 1},
	"filter-id":                 {vendorID: 0, typ: 11},
	"reply-message":             {vendorID: 0, typ: 18},
	"class":                     {vendorID: 0, typ: 25},
	"mikrotik-group":            {vendorID: radiusMikrotikVendorID, typ: 3},
	"mikrotik-realm":            {vendorID: radiusMikrotikVendorID, typ: 9},
	"mikrotik-address-list":     {vendorID: radiusMikrotikVendorID, typ: 19},
	"mikrotik-wireless-comment": {vendorID: radiusMikrotikVendorID, typ: 21},
}

// parseRadiusAttrRef accepts a well known attribute name (e.g. Filter-Id,
// Mikrotik-Group), a bare standard attribute number, or the generic form
// vsa:<vendor-id>:<type>. An empty string yields an unset reference.
func parseRadiusAttrRef(s string) (radiusAttrRef, error) {
	key := strings.ToLower(strings.TrimSpace(s))
	if key == "" {
		return radiusAttrRef{}, nil
	}

	if ref, ok := radiusKnownAttrs[key]; ok {
		ref.name = s

		return ref, nil
	}

	if strings.HasPrefix(key, "vsa:") {
		parts := strings.Split(key, ":")
		if len(parts) != 3 {
			return radiusAttrRef{}, fmt.Errorf("radius attribute %q: expected vsa:<vendor-id>:<type>", s)
		}

		vendorID, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil || vendorID == 0 {
			return radiusAttrRef{}, fmt.Errorf("radius attribute %q: invalid vendor id", s)
		}

		typ, err := strconv.ParseUint(parts[2], 10, 8)
		if err != nil || typ == 0 {
			return radiusAttrRef{}, fmt.Errorf("radius attribute %q: invalid type", s)
		}

		return radiusAttrRef{name: s, vendorID: uint32(vendorID), typ: byte(typ)}, nil
	}

	if typ, err := strconv.ParseUint(key, 10, 8); err == nil && typ > 0 {
		return radiusAttrRef{name: s, typ: byte(typ)}, nil
	}

	return radiusAttrRef{}, fmt.Errorf("radius attribute %q: unknown attribute", s)
}

func (r radiusAttrRef) valid() bool {
	return r.typ != 0
}

// values returns every string value of the attribute found in the packet.
func (r radiusAttrRef) values(p *radius.Packet) []string {
	if !r.valid() {
		return nil
	}

	var out []string

	for _, avp := range p.Attributes {
		if r.vendorID == 0 {
			if byte(avp.Type) == r.typ {
				out = append(out, radius.String(avp.Attribute))
			}

			continue
		}

		if avp.Type != rfc2865.VendorSpecific_Type {
			continue
		}

		vendorID, value, err := radius.VendorSpecific(avp.Attribute)
		if err != nil || vendorID != r.vendorID {
			continue
		}

		// A VSA may carry several sub-attributes, each encoded as type, length, value.
		for len(value) >= 2 {
			l := int(value[1])
			if l < 2 || l > len(value) {
				break
			}

			if value[0] == r.typ {
				out = append(out, string(value[2:l]))
			}

			value = value[l:]
		}
	}

	return out
}

// radiusEntry holds what was learned from an Access-Accept for a user.
type radiusEntry struct {
	superuser bool
	groups    []string
	rules     []radiusACLRule
}

// RADIUS authenticates users against a RADIUS server (RFC 2865) over UDP or
// RadSec (RFC 6614). Superuser and ACL checks are answered from the attributes
// cached at authentication time, since RADIUS offers no way to query a user
// without their password.
type RADIUS struct {
	Servers                     []string
	Protocol                    string
	Secret                      []byte
	Timeout                     time.Duration
	Retries                     int
	NASIdentifier               string
	NASIPAddress                net.IP
	AuthProtocol                string
	SuperuserAttr               radiusAttrRef
	SuperuserValue              string
	AclAttr                     radiusAttrRef
	GroupAttr                   radiusAttrRef
	AclFile                     string
	AclDefaultAllow             bool
	RequireMessageAuthenticator bool
	CacheTTL                    time.Duration

	transports []radiusTransport
	groupACL   *radiusGroupACL
	cache      *ttlcache.Cache[string, *radiusEntry]
}

func NewRADIUS(authOpts map[string]string, logLevel log.Level) (*RADIUS, error) {
	log.SetLevel(logLevel)

	r := &RADIUS{
		Protocol:       radiusProtocolUDP,
		Timeout:        radiusDefaultTimeout,
		Retries:        radiusDefaultRetries,
		NASIdentifier:  "mosquitto",
		AuthProtocol:   radiusAuthPAP,
		SuperuserValue: "mqtt-superuser",
		CacheTTL:       radiusDefaultCacheTTL,
	}

	missingOptions := ""

	if protocol, ok := authOpts["radius_protocol"]; ok {
		switch strings.ToLower(strings.TrimSpace(protocol)) {
		case radiusProtocolUDP, radiusProtocolRadSec:
			r.Protocol = strings.ToLower(strings.TrimSpace(protocol))
		default:
			return nil, fmt.Errorf("RADIUS backend error: unknown radius_protocol %q, expected udp or radsec", protocol)
		}
	}

	defaultPort := radiusDefaultUDPPort
	if r.Protocol == radiusProtocolRadSec {
		defaultPort = radiusDefaultRadSecPort
	}

	if servers, ok := authOpts["radius_servers"]; ok {
		for _, s := range strings.Split(servers, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}

			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(strings.Trim(s, "[]"), defaultPort)
			}

			r.Servers = append(r.Servers, s)
		}
	}

	if len(r.Servers) == 0 {
		missingOptions += " radius_servers"
	}

	if r.Protocol == radiusProtocolRadSec {
		r.Secret = []byte(radiusRadSecSecret)

		if secret, ok := authOpts["radius_secret"]; ok && secret != "" && secret != radiusRadSecSecret {
			log.Warnf("radius: radius_secret is ignored with radsec, the secret is always %q", radiusRadSecSecret)
		}
	} else if secret, ok := authOpts["radius_secret"]; ok && secret != "" {
		r.Secret = []byte(secret)
	} else {
		missingOptions += " radius_secret"
	}

	if timeout, ok := authOpts["radius_timeout_ms"]; ok {
		ms, err := strconv.Atoi(strings.TrimSpace(timeout))
		if err != nil || ms <= 0 {
			return nil, fmt.Errorf("RADIUS backend error: invalid radius_timeout_ms %q", timeout)
		}

		r.Timeout = time.Duration(ms) * time.Millisecond
	}

	if retries, ok := authOpts["radius_retries"]; ok {
		n, err := strconv.Atoi(strings.TrimSpace(retries))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("RADIUS backend error: invalid radius_retries %q", retries)
		}

		r.Retries = n
	}

	if nasID, ok := authOpts["radius_nas_identifier"]; ok && strings.TrimSpace(nasID) != "" {
		r.NASIdentifier = strings.TrimSpace(nasID)
	}

	if nasIP, ok := authOpts["radius_nas_ip"]; ok && strings.TrimSpace(nasIP) != "" {
		ip := net.ParseIP(strings.TrimSpace(nasIP))
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("RADIUS backend error: radius_nas_ip %q is not an IPv4 address", nasIP)
		}

		r.NASIPAddress = ip.To4()
	}

	if authProtocol, ok := authOpts["radius_auth_protocol"]; ok {
		switch strings.ToLower(strings.TrimSpace(authProtocol)) {
		case radiusAuthPAP, radiusAuthCHAP:
			r.AuthProtocol = strings.ToLower(strings.TrimSpace(authProtocol))
		default:
			return nil, fmt.Errorf("RADIUS backend error: unknown radius_auth_protocol %q, expected pap or chap", authProtocol)
		}
	}

	if ttl, ok := authOpts["radius_attr_cache_seconds"]; ok {
		seconds, err := strconv.Atoi(strings.TrimSpace(ttl))
		if err != nil || seconds <= 0 {
			return nil, fmt.Errorf("RADIUS backend error: invalid radius_attr_cache_seconds %q", ttl)
		}

		r.CacheTTL = time.Duration(seconds) * time.Second
	}

	var err error

	r.SuperuserAttr, err = parseRadiusAttrRef(radiusOpt(authOpts, "radius_superuser_attr", "Mikrotik-Group"))
	if err != nil {
		return nil, fmt.Errorf("RADIUS backend error: radius_superuser_attr: %w", err)
	}

	if value, ok := authOpts["radius_superuser_value"]; ok {
		r.SuperuserValue = strings.TrimSpace(value)
	}

	r.AclAttr, err = parseRadiusAttrRef(radiusOpt(authOpts, "radius_acl_attr", "Filter-Id"))
	if err != nil {
		return nil, fmt.Errorf("RADIUS backend error: radius_acl_attr: %w", err)
	}

	r.GroupAttr, err = parseRadiusAttrRef(radiusOpt(authOpts, "radius_group_attr", "Mikrotik-Group"))
	if err != nil {
		return nil, fmt.Errorf("RADIUS backend error: radius_group_attr: %w", err)
	}

	if aclDefault, ok := authOpts["radius_acl_default"]; ok {
		switch strings.ToLower(strings.TrimSpace(aclDefault)) {
		case "allow":
			r.AclDefaultAllow = true
		case "deny":
			r.AclDefaultAllow = false
		default:
			return nil, fmt.Errorf("RADIUS backend error: unknown radius_acl_default %q, expected allow or deny", aclDefault)
		}
	}

	if require, ok := authOpts["radius_require_message_authenticator"]; ok && strings.TrimSpace(require) == "true" {
		r.RequireMessageAuthenticator = true
	}

	if missingOptions != "" {
		return nil, fmt.Errorf("RADIUS backend error: missing options:%s", missingOptions)
	}

	if aclFile, ok := authOpts["radius_acl_file"]; ok && strings.TrimSpace(aclFile) != "" {
		r.AclFile = strings.TrimSpace(aclFile)

		r.groupACL, err = newRadiusGroupACL(r.AclFile)
		if err != nil {
			return nil, fmt.Errorf("RADIUS backend error: acl file: %w", err)
		}
	}

	for _, server := range r.Servers {
		if r.Protocol == radiusProtocolRadSec {
			host, _, _ := net.SplitHostPort(server)

			verify := true
			if v, ok := authOpts["radius_tls_verify"]; ok && strings.TrimSpace(v) == "false" {
				verify = false
			}

			tlsConfig, err := newRadSecTLSConfig(
				strings.TrimSpace(authOpts["radius_tls_ca"]),
				strings.TrimSpace(authOpts["radius_tls_cert"]),
				strings.TrimSpace(authOpts["radius_tls_key"]),
				host,
				verify,
			)
			if err != nil {
				r.Halt()

				return nil, fmt.Errorf("RADIUS backend error: %w", err)
			}

			r.transports = append(r.transports, newRadiusRadSecTransport(server, tlsConfig))
		} else {
			r.transports = append(r.transports, newRadiusUDPTransport(server))
		}
	}

	r.cache = ttlcache.New[string, *radiusEntry](
		ttlcache.WithTTL[string, *radiusEntry](r.CacheTTL),
	)
	go r.cache.Start()

	log.Infof("radius: backend ready, protocol %s, servers %s, auth %s", r.Protocol, strings.Join(r.Servers, ","), r.AuthProtocol)

	return r, nil
}

func radiusOpt(authOpts map[string]string, key, def string) string {
	if v, ok := authOpts[key]; ok {
		return v
	}

	return def
}

// GetUser sends an Access-Request and caches the attributes of an Access-Accept.
func (r *RADIUS) GetUser(username, password, clientid string) (bool, error) {
	if username == "" {
		return false, nil
	}

	req := radius.New(radius.CodeAccessRequest, r.Secret)

	if err := rfc2865.UserName_SetString(req, username); err != nil {
		return false, fmt.Errorf("radius: user-name: %w", err)
	}

	switch r.AuthProtocol {
	case radiusAuthCHAP:
		if err := radiusSetCHAP(req, password); err != nil {
			return false, fmt.Errorf("radius: chap: %w", err)
		}
	default:
		if err := rfc2865.UserPassword_SetString(req, password); err != nil {
			return false, fmt.Errorf("radius: user-password: %w", err)
		}
	}

	if err := rfc2865.NASIdentifier_SetString(req, r.NASIdentifier); err != nil {
		return false, fmt.Errorf("radius: nas-identifier: %w", err)
	}

	if r.NASIPAddress != nil {
		if err := rfc2865.NASIPAddress_Set(req, r.NASIPAddress); err != nil {
			return false, fmt.Errorf("radius: nas-ip-address: %w", err)
		}
	}

	if err := rfc2865.ServiceType_Set(req, rfc2865.ServiceType_Value_LoginUser); err != nil {
		return false, fmt.Errorf("radius: service-type: %w", err)
	}

	if clientid != "" {
		if err := rfc2865.CallingStationID_SetString(req, clientid); err != nil {
			return false, fmt.Errorf("radius: calling-station-id: %w", err)
		}
	}

	wire, err := radiusEncodeRequest(req)
	if err != nil {
		return false, fmt.Errorf("radius: encode: %w", err)
	}

	raw, err := r.exchange(wire)
	if err != nil {
		return false, err
	}

	if !radius.IsAuthenticResponse(raw, wire, r.Secret) {
		return false, errors.New("radius: response authenticator mismatch (wrong shared secret?)")
	}

	present, valid := radiusVerifyMessageAuthenticator(raw, wire[4:20], r.Secret)
	if present && !valid {
		return false, errors.New("radius: response message-authenticator mismatch")
	}

	if !present && r.RequireMessageAuthenticator {
		return false, errors.New("radius: response lacks message-authenticator")
	}

	resp, err := radius.Parse(raw, r.Secret)
	if err != nil {
		return false, fmt.Errorf("radius: parse response: %w", err)
	}

	switch resp.Code {
	case radius.CodeAccessAccept:
		entry := r.buildEntry(resp, username)
		r.cache.Set(username, entry, ttlcache.DefaultTTL)

		log.Debugf("radius: user %s accepted (superuser=%t, groups=%v, rules=%d)", username, entry.superuser, entry.groups, len(entry.rules))

		return true, nil
	case radius.CodeAccessReject:
		log.Debugf("radius: user %s rejected: %s", username, rfc2865.ReplyMessage_GetString(resp))

		return false, nil
	case radius.CodeAccessChallenge:
		log.Warnf("radius: user %s got an Access-Challenge, interactive authentication is not supported", username)

		return false, nil
	default:
		return false, fmt.Errorf("radius: unexpected response code %s", resp.Code)
	}
}

// exchange tries every server in order, with the configured retries each.
func (r *RADIUS) exchange(wire []byte) ([]byte, error) {
	var lastErr error

	for _, transport := range r.transports {
		for attempt := 0; attempt <= r.Retries; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
			raw, err := transport.Exchange(ctx, wire)
			cancel()

			if err == nil {
				return raw, nil
			}

			lastErr = err

			log.Debugf("radius: server %s attempt %d/%d failed: %s", transport.Addr(), attempt+1, r.Retries+1, err)
		}

		log.Warnf("radius: server %s did not answer", transport.Addr())
	}

	return nil, fmt.Errorf("radius: no server answered: %w", lastErr)
}

// radiusSetCHAP adds CHAP-Challenge and CHAP-Password (RFC 2865 §5.3).
func radiusSetCHAP(req *radius.Packet, password string) error {
	buf := make([]byte, 17)
	if _, err := rand.Read(buf); err != nil {
		return err
	}

	ident := buf[0]
	challenge := buf[1:]

	h := md5.New()
	h.Write([]byte{ident})
	h.Write([]byte(password))
	h.Write(challenge)

	if err := rfc2865.CHAPChallenge_Set(req, challenge); err != nil {
		return err
	}

	return rfc2865.CHAPPassword_Set(req, append([]byte{ident}, h.Sum(nil)...))
}

func (r *RADIUS) buildEntry(resp *radius.Packet, username string) *radiusEntry {
	entry := &radiusEntry{}

	if r.SuperuserValue != "" {
		for _, v := range r.SuperuserAttr.values(resp) {
			if v == r.SuperuserValue {
				entry.superuser = true

				break
			}
		}
	}

	entry.groups = r.GroupAttr.values(resp)

	for _, v := range r.AclAttr.values(resp) {
		rule, err := parseRadiusACLRule(v)
		if err != nil {
			log.Warnf("radius: ignoring acl attribute for user %s: %s", username, err)

			continue
		}

		entry.rules = append(entry.rules, rule)
	}

	return entry
}

// GetSuperuser answers from the attributes cached at authentication time.
func (r *RADIUS) GetSuperuser(username string) (bool, error) {
	item := r.cache.Get(username)
	if item == nil {
		return false, nil
	}

	return item.Value().superuser, nil
}

// CheckAcl answers from the attributes cached at authentication time plus the
// group ACL file. Without any applicable rule, radius_acl_default decides.
func (r *RADIUS) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {
	item := r.cache.Get(username)
	if item == nil {
		log.Debugf("radius: no cached attributes for user %s, applying default", username)

		return r.AclDefaultAllow, nil
	}

	entry := item.Value()

	rules := make([]radiusACLRule, 0, len(entry.rules))
	rules = append(rules, entry.rules...)

	if r.groupACL != nil {
		rules = append(rules, r.groupACL.rulesFor(entry.groups)...)
	}

	if len(rules) == 0 {
		return r.AclDefaultAllow, nil
	}

	return radiusCheckACL(rules, username, clientid, topic, acc), nil
}

func (r *RADIUS) GetName() string {
	return "RADIUS"
}

func (r *RADIUS) Halt() {
	for _, transport := range r.transports {
		if err := transport.Close(); err != nil {
			log.Errorf("radius: closing %s: %s", transport.Addr(), err)
		}
	}

	if r.cache != nil {
		r.cache.Stop()
	}

	if r.groupACL != nil {
		r.groupACL.stop()
	}
}
