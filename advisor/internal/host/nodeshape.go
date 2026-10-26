package host

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"aperire-advisor/internal/runbook"
)

// One structured reading of the deployment an operator actually has.
//
// Aperire One runs on other people's setups, and most of the people running
// them are not xrpld experts (operator requirement, 2026-09-27). So the
// Advisor reads the compose it finds rather than assuming one layout,
// changes only what an operation needs, and says what it thinks of the rest.
// This is that reading. What to think of it is findings.go.
//
// Three sources, and none of them an assumption:
//
//   - the RESOLVED deployment, through the wrapper's compose-config verb,
//     so an .env, an extends: or a profile is already applied. Reading the
//     raw file would be reading what somebody typed rather than what
//     compose will do.
//   - the node's own config, for the paths it names. The debug log path
//     comes from [debug_logfile], never from a fixed /var/log/xrpld: on
//     production it is /var/log/rippled/debug.log, and judging that path's
//     writability against the wrong directory would be advice about a file
//     nobody has.
//   - the running container, for the account and the stop grace it was
//     actually created with, which is what a stop gets.
//
// Where it cannot measure, it says so. Read=false with a note, never a
// zero, following #679: a check nobody could run must not read as a pass.

// MountFact is one bind, as compose resolved it.
type MountFact struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// PortFact is one published port, with the interface it is published on.
// The interface is the whole point: 5005 on 127.0.0.1 and 5005 on 0.0.0.0
// are not the same deployment.
type PortFact struct {
	HostIP    string `json:"host_ip"`
	Published string `json:"published"`
	Target    int    `json:"target"`
	Protocol  string `json:"protocol"`
}

// HealthFact is the container's healthcheck and, for the shape this project
// writes, the server states it treats as healthy.
type HealthFact struct {
	Test        []string `json:"test"`
	Interval    string   `json:"interval"`
	StartPeriod string   `json:"start_period"`
	// States is what the test accepts, when it is the server_state shape
	// every compose in this project uses. Empty for a test this cannot
	// read, which is a real answer and not an empty list of states.
	States []string `json:"states"`
	// Read is false when there is no healthcheck at all.
	Read bool `json:"read"`
}

// NodeShape is the profile. It extends RuntimeShape rather than sitting
// beside it, so every precondition that already reads those four fields
// keeps reading exactly the same thing.
type NodeShape struct {
	runbook.RuntimeShape

	Service string `json:"service"`

	// Where the files are
	ConfigMounts     []MountFact `json:"config_mounts"`
	ValidatorsMounts []MountFact `json:"validators_mounts"`
	DataMount        MountFact   `json:"data_mount"`
	// Mounts is every bind, in the order the deployment lists them. The
	// three above are the ones with names; this is what "is this path on
	// a volume" is actually answered against, because an operator who
	// mounts ./logs at /var/log/rippled has done exactly the right thing
	// and a reading that only knew the config and the data would tell
	// them their log dies with the container.
	Mounts []MountFact `json:"mounts"`
	DataPathInConfig string      `json:"data_path_in_config"`
	// LogPathInConfig is [debug_logfile], empty when the config sets none.
	LogPathInConfig string `json:"log_path_in_config"`
	// LogOnVolume says that path is inside a mount rather than in the
	// container layer, which is the difference between a log that survives
	// a recreate and one that does not.
	LogOnVolume bool `json:"log_on_volume"`

	// What it runs
	ImageRef           string      `json:"image_ref"`
	ImageOrigin        ImageOrigin `json:"image_origin"`
	PullPolicy         string      `json:"pull_policy"`
	EntrypointOverride []string    `json:"entrypoint_override"`
	CommandOverride    []string    `json:"command_override"`
	// ArgsWrittenDown is true when the deployment names both, so the
	// arguments the node runs with do not come from whichever image it
	// happens to be pointed at.
	ArgsWrittenDown bool `json:"args_written_down"`
	// Silent is --silent among those arguments. An upgrade-blocking
	// finding: docker logs is where the rotation guard and the can-delete
	// timer read what the store is doing.
	Silent bool `json:"silent"`

	// How it is held
	RestartPolicy   string     `json:"restart_policy"`
	StopGraceFile   string     `json:"stop_grace_file"`
	Healthcheck     HealthFact `json:"healthcheck"`
	Ports           []PortFact `json:"ports"`
	CapDrop         []string   `json:"cap_drop"`
	NoNewPrivileges bool       `json:"no_new_privileges"`
	MemLimit        string     `json:"mem_limit"`
	CPUs            string     `json:"cpus"`
	NetworkMode     string     `json:"network_mode"`
	LogDriver       string     `json:"log_driver"`
	LogMaxSize      string     `json:"log_max_size"`
	LogMaxFile      string     `json:"log_max_file"`
	Init            bool       `json:"init"`

	// Read is false when the deployment could not be resolved at all.
	Read bool `json:"read"`
	// Notes is what could not be read, and why. Never a silent gap.
	Notes []string `json:"notes,omitempty"`
}

// composeConfig is the subset of `docker compose config --format json` this
// reads. Deliberately a subset: `environment` has no field here and is
// never carried anywhere, so a compose that keeps a secret in it cannot
// reach the model through this path.
type composeConfig struct {
	Services map[string]struct {
		Image           string          `json:"image"`
		PullPolicy      string          `json:"pull_policy"`
		User            string          `json:"user"`
		Entrypoint      json.RawMessage `json:"entrypoint"`
		Command         json.RawMessage `json:"command"`
		Restart         string          `json:"restart"`
		StopGracePeriod string          `json:"stop_grace_period"`
		Init            bool            `json:"init"`
		NetworkMode     string          `json:"network_mode"`
		MemLimit        json.RawMessage `json:"mem_limit"`
		CPUs            json.RawMessage `json:"cpus"`
		CapDrop         []string        `json:"cap_drop"`
		SecurityOpt     []string        `json:"security_opt"`
		Ports           []PortFact      `json:"ports"`
		Volumes         []struct {
			Type     string `json:"type"`
			Source   string `json:"source"`
			Target   string `json:"target"`
			ReadOnly bool   `json:"read_only"`
		} `json:"volumes"`
		Logging struct {
			Driver  string            `json:"driver"`
			Options map[string]string `json:"options"`
		} `json:"logging"`
		Healthcheck *struct {
			Test        []string `json:"test"`
			Interval    string   `json:"interval"`
			StartPeriod string   `json:"start_period"`
		} `json:"healthcheck"`
	} `json:"services"`
}

// NodeShapeNow reads the profile.
//
// A native host has no deployment to profile and says so rather than
// refusing: an origin a host does not have is not a fault (#679's rule
// applied to a whole reading).
func (s *State) NodeShapeNow() NodeShape {
	var sh NodeShape
	sh.Service = s.Profile.Service
	if s.Kind() == "native" {
		sh.Notes = append(sh.Notes, "a native host runs no container, so there is no deployment to read")
		return sh
	}
	// The four RuntimeShape fields first, from the same reading every
	// existing precondition already uses, so nothing that reads them
	// starts seeing a different answer.
	if rs, err := s.RuntimeAccount(); err == nil {
		sh.RuntimeShape = rs
	} else {
		sh.Notes = append(sh.Notes, "the running container's account could not be read: "+err.Error())
	}

	out, err := s.wrapperOut("compose-config")
	if err != nil {
		sh.Notes = append(sh.Notes, "the deployment could not be resolved: "+err.Error())
		return sh
	}
	if err := sh.readCompose(out, s.Profile.Service); err != nil {
		sh.Notes = append(sh.Notes, err.Error())
		return sh
	}
	sh.Read = true

	// The node's own config, for the two paths that are its to name.
	if cfg, err := s.NodeConfiguration(); err == nil {
		// Both are the stanza shape: a header whose value is the line
		// under it. The path is read from the config, never assumed to be
		// the image's /var/log/xrpld. Production's is
		// /var/log/rippled/debug.log, and judging the wrong directory's
		// writability would be advice about a file nobody has.
		if v, ok := cfg.StanzaValue("debug_logfile"); ok {
			sh.LogPathInConfig = strings.TrimSpace(v)
		}
		if v, ok := cfg.StanzaValue("database_path"); ok {
			sh.DataPathInConfig = strings.TrimSpace(v)
		}
	} else {
		sh.Notes = append(sh.Notes,
			"the node's own config could not be read, so its log and data paths are not measured: "+err.Error())
	}
	sh.LogOnVolume = sh.pathIsOnAMount(sh.LogPathInConfig)
	return sh
}

// readCompose fills the shape from the resolved deployment.
func (sh *NodeShape) readCompose(body, service string) error {
	var c composeConfig
	if err := json.Unmarshal([]byte(body), &c); err != nil {
		return fmt.Errorf("the resolved deployment could not be read: %v", err)
	}
	svc, ok := c.Services[service]
	if !ok {
		names := make([]string, 0, len(c.Services))
		for n := range c.Services {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("the resolved deployment names no service %q (it has %s)",
			service, strings.Join(names, ", "))
	}
	sh.ImageRef = svc.Image
	sh.ImageOrigin = OriginOf(svc.Image)
	sh.PullPolicy = svc.PullPolicy
	if svc.User != "" {
		sh.ComposeUser = svc.User
	}
	sh.EntrypointOverride = stringList(svc.Entrypoint)
	sh.CommandOverride = stringList(svc.Command)
	sh.ArgsWrittenDown = len(sh.EntrypointOverride) > 0 && len(sh.CommandOverride) > 0
	for _, a := range append(append([]string{}, sh.EntrypointOverride...), sh.CommandOverride...) {
		if a == "--silent" {
			sh.Silent = true
		}
	}
	sh.RestartPolicy = svc.Restart
	sh.StopGraceFile = svc.StopGracePeriod
	sh.Init = svc.Init
	sh.NetworkMode = svc.NetworkMode
	sh.MemLimit = scalar(svc.MemLimit)
	sh.CPUs = scalar(svc.CPUs)
	sh.CapDrop = svc.CapDrop
	for _, o := range svc.SecurityOpt {
		if strings.HasPrefix(o, "no-new-privileges") && !strings.HasSuffix(o, "false") {
			sh.NoNewPrivileges = true
		}
	}
	sh.Ports = svc.Ports
	sh.LogDriver = svc.Logging.Driver
	sh.LogMaxSize = svc.Logging.Options["max-size"]
	sh.LogMaxFile = svc.Logging.Options["max-file"]

	for _, v := range svc.Volumes {
		if v.Type != "bind" && v.Type != "" {
			continue
		}
		m := MountFact{Source: v.Source, Target: v.Target, ReadOnly: v.ReadOnly}
		sh.Mounts = append(sh.Mounts, m)
		switch {
		case strings.HasSuffix(v.Target, "/rippled.cfg"), strings.HasSuffix(v.Target, "/xrpld.cfg"):
			sh.ConfigMounts = append(sh.ConfigMounts, m)
			if v.Target == EtcConfigPath {
				sh.ConfigAtEtc = true
			}
		case strings.HasSuffix(v.Target, "/validators.txt"):
			sh.ValidatorsMounts = append(sh.ValidatorsMounts, m)
		case strings.HasPrefix(v.Target, "/var/lib/"):
			sh.DataMount = m
		}
	}
	if sh.Healthcheck.Read = svc.Healthcheck != nil && len(svc.Healthcheck.Test) > 0; sh.Healthcheck.Read {
		sh.Healthcheck.Test = svc.Healthcheck.Test
		sh.Healthcheck.Interval = svc.Healthcheck.Interval
		sh.Healthcheck.StartPeriod = svc.Healthcheck.StartPeriod
		sh.Healthcheck.States = serverStatesIn(strings.Join(svc.Healthcheck.Test, " "))
	}
	return nil
}

// pathIsOnAMount says whether a path inside the container lands on a bind
// rather than in the container's own layer. A log in the layer is lost on
// every recreate, which is the first thing anyone wants after an incident.
func (sh *NodeShape) pathIsOnAMount(p string) bool {
	if p == "" {
		return false
	}
	for _, m := range sh.Mounts {
		if m.Target == "" {
			continue
		}
		if p == m.Target || strings.HasPrefix(p, strings.TrimSuffix(m.Target, "/")+"/") {
			return true
		}
	}
	return false
}

// serverStatesIn reads the states a healthcheck accepts out of the
// server_state test every compose in this project writes. Empty for a test
// this does not recognise, which is "not measured", not "no states".
func serverStatesIn(test string) []string {
	i := strings.Index(test, `"server_state"`)
	if i < 0 {
		return nil
	}
	rest := test[i:]
	open := strings.Index(rest, "(")
	closing := strings.Index(rest, ")")
	if open < 0 || closing < open {
		return nil
	}
	var out []string
	for _, s := range strings.Split(rest[open+1:closing], "|") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// stringList reads compose's "a string, a list of strings, or null" shape.
func stringList(raw json.RawMessage) []string {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && one != "" {
		return strings.Fields(one)
	}
	return nil
}

// scalar reads compose's "a number or a string" shape, for mem_limit and
// cpus, which it emits as bytes and as a float respectively.
func scalar(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "0" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil && f > 0 {
		if f >= 1<<30 {
			return strconv.FormatFloat(f/(1<<30), 'g', -1, 64) + "g"
		}
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	return strings.Trim(string(raw), `"`)
}

// NodeShape is the narrow view a precondition reads, derived from the full
// profile so there is one reading and not two.
func (s *State) NodeShape() runbook.DeploymentShape {
	sh := s.NodeShapeNow()
	return runbook.DeploymentShape{
		Read:            sh.Read,
		Notes:           sh.Notes,
		ConfigAtEtc:     sh.ConfigAtEtc,
		ArgsWrittenDown: sh.ArgsWrittenDown,
		Silent:          sh.Silent,
		CommandOverride: sh.CommandOverride,

		EntrypointOverride: sh.EntrypointOverride,
	}
}
