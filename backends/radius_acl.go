package backends

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	. "github.com/iegomez/mosquitto-go-auth/backends/constants"
	"github.com/iegomez/mosquitto-go-auth/backends/topics"
	log "github.com/sirupsen/logrus"
)

// radiusACLRule is a single topic rule, either received from the RADIUS
// server (e.g. in Filter-Id) or read from the group ACL file.
type radiusACLRule struct {
	topic string
	acc   int32
}

var radiusACLAccess = map[string]int32{
	"read":      MOSQ_ACL_READ,
	"write":     MOSQ_ACL_WRITE,
	"readwrite": MOSQ_ACL_READWRITE,
	"subscribe": MOSQ_ACL_SUBSCRIBE,
	"deny":      MOSQ_ACL_DENY,
}

func parseRadiusACLAccess(s string) (int32, bool) {
	s = strings.ToLower(strings.TrimSpace(s))

	if acc, ok := radiusACLAccess[s]; ok {
		return acc, true
	}

	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}

	switch int32(n) {
	case MOSQ_ACL_READ, MOSQ_ACL_WRITE, MOSQ_ACL_READWRITE, MOSQ_ACL_SUBSCRIBE, MOSQ_ACL_DENY:
		return int32(n), true
	}

	return 0, false
}

// parseRadiusACLRule parses a rule in the form "<access>:<topic pattern>",
// e.g. "readwrite:sensors/%u/#". Access may be read, write, readwrite,
// subscribe, deny or the numeric mosquitto value.
func parseRadiusACLRule(s string) (radiusACLRule, error) {
	s = strings.TrimSpace(s)

	i := strings.Index(s, ":")
	if i < 0 {
		return radiusACLRule{}, fmt.Errorf("radius acl rule %q: expected <access>:<topic>", s)
	}

	acc, ok := parseRadiusACLAccess(s[:i])
	if !ok {
		return radiusACLRule{}, fmt.Errorf("radius acl rule %q: unknown access %q", s, s[:i])
	}

	topic := strings.TrimSpace(s[i+1:])
	if topic == "" {
		return radiusACLRule{}, fmt.Errorf("radius acl rule %q: empty topic", s)
	}

	return radiusACLRule{topic: topic, acc: acc}, nil
}

// radiusExpandTopic replaces %u and %c placeholders.
func radiusExpandTopic(pattern, username, clientid string) string {
	pattern = strings.ReplaceAll(pattern, "%u", username)

	return strings.ReplaceAll(pattern, "%c", clientid)
}

// radiusAccessAllows mirrors the semantics of the files backend.
func radiusAccessAllows(ruleAcc, acc int32, topic string) bool {
	if acc == ruleAcc || ruleAcc == MOSQ_ACL_READWRITE {
		return true
	}

	if acc == MOSQ_ACL_SUBSCRIBE && topic != "#" && (ruleAcc == MOSQ_ACL_READ || ruleAcc == MOSQ_ACL_SUBSCRIBE) {
		return true
	}

	return false
}

// radiusCheckACL evaluates rules for a topic: any matching deny rule wins,
// otherwise the first matching rule with sufficient access grants it.
func radiusCheckACL(rules []radiusACLRule, username, clientid, topic string, acc int32) bool {
	for _, rule := range rules {
		if rule.acc != MOSQ_ACL_DENY {
			continue
		}

		if topics.Match(radiusExpandTopic(rule.topic, username, clientid), topic) {
			return false
		}
	}

	for _, rule := range rules {
		if rule.acc == MOSQ_ACL_DENY {
			continue
		}

		if !topics.Match(radiusExpandTopic(rule.topic, username, clientid), topic) {
			continue
		}

		if radiusAccessAllows(rule.acc, acc, topic) {
			return true
		}
	}

	return false
}

// radiusGroupACL holds topic rules per group read from a file. Rules placed
// before the first "group" line apply to every authenticated user.
//
// File format (only whole-line comments are supported, since "#" is also the
// MQTT wildcard):
//
//	# comment
//	topic read status/#
//	group sensors
//	topic readwrite sensors/%u/#
//	topic deny sensors/%u/private
type radiusGroupACL struct {
	sync.RWMutex
	path    string
	common  []radiusACLRule
	groups  map[string][]radiusACLRule
	signals chan os.Signal
}

func newRadiusGroupACL(path string) (*radiusGroupACL, error) {
	g := &radiusGroupACL{path: path}

	if err := g.load(); err != nil {
		return nil, err
	}

	g.signals = make(chan os.Signal, 1)
	signal.Notify(g.signals, syscall.SIGHUP)

	go g.watchSignals()

	return g, nil
}

func (g *radiusGroupACL) watchSignals() {
	for range g.signals {
		if err := g.load(); err != nil {
			log.Errorf("radius: reload of acl file %s failed: %s", g.path, err)
		} else {
			log.Infof("radius: acl file %s reloaded", g.path)
		}
	}
}

func (g *radiusGroupACL) stop() {
	if g.signals != nil {
		signal.Stop(g.signals)
		close(g.signals)
	}
}

func (g *radiusGroupACL) load() error {
	file, err := os.Open(g.path)
	if err != nil {
		return err
	}
	defer file.Close()

	common := []radiusACLRule{}
	groups := map[string][]radiusACLRule{}
	current := ""

	scanner := bufio.NewScanner(file)
	lineNo := 0

	for scanner.Scan() {
		lineNo++

		// "#" is the MQTT multi-level wildcard, so only whole-line comments are supported.
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)

		switch strings.ToLower(fields[0]) {
		case "group":
			if len(fields) != 2 {
				return fmt.Errorf("%s:%d: expected \"group <name>\"", g.path, lineNo)
			}

			current = fields[1]
			if _, ok := groups[current]; !ok {
				groups[current] = []radiusACLRule{}
			}
		case "topic", "pattern":
			if len(fields) < 2 {
				return fmt.Errorf("%s:%d: expected \"topic [access] <pattern>\"", g.path, lineNo)
			}

			rule := radiusACLRule{acc: MOSQ_ACL_READWRITE}
			rest := fields[1:]

			if len(rest) > 1 {
				if acc, ok := parseRadiusACLAccess(rest[0]); ok {
					rule.acc = acc
					rest = rest[1:]
				}
			}

			rule.topic = strings.Join(rest, " ")

			if current == "" {
				common = append(common, rule)
			} else {
				groups[current] = append(groups[current], rule)
			}
		default:
			return fmt.Errorf("%s:%d: unknown directive %q", g.path, lineNo, fields[0])
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	g.Lock()
	g.common = common
	g.groups = groups
	g.Unlock()

	log.Debugf("radius: loaded %d common rules and %d groups from %s", len(common), len(groups), g.path)

	return nil
}

// rulesFor returns the common rules followed by the rules of every given group.
func (g *radiusGroupACL) rulesFor(groups []string) []radiusACLRule {
	g.RLock()
	defer g.RUnlock()

	rules := make([]radiusACLRule, 0, len(g.common))
	rules = append(rules, g.common...)

	for _, name := range groups {
		rules = append(rules, g.groups[name]...)
	}

	return rules
}
