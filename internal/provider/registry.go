package provider

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/ini.v1"
)

const (
	systemDir = "/usr/share/dbus-passkey/providers.d"
	etcDir    = "/etc/dbus-passkey/providers.d"
)

// Registry holds loaded provider entries.
type Registry struct {
	mu      sync.RWMutex
	entries []RegistryEntry
}

func NewRegistry() *Registry {
	r := &Registry{}
	r.Reload()
	return r
}

func (r *Registry) Reload() {
	entries := loadDirs(systemDir, etcDir)
	r.mu.Lock()
	r.entries = entries
	r.mu.Unlock()
	log.Printf("provider registry: loaded %d entries", len(entries))
}

func (r *Registry) Entries() []RegistryEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RegistryEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

func loadDirs(dirs ...string) []RegistryEntry {
	seen := map[string]RegistryEntry{}
	for _, dir := range dirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.conf"))
		if err != nil || files == nil {
			continue
		}
		for _, f := range files {
			e, err := loadFile(f)
			if err != nil {
				log.Printf("provider registry: skip %s: %v", f, err)
				continue
			}
			seen[e.ID] = e // later dir (etc) overrides earlier
		}
	}
	out := make([]RegistryEntry, 0, len(seen))
	for _, e := range seen {
		out = append(out, e)
	}
	return out
}

func loadFile(path string) (RegistryEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return RegistryEntry{}, err
	}
	defer f.Close()

	cfg, err := ini.Load(f)
	if err != nil {
		return RegistryEntry{}, err
	}
	sec := cfg.Section("Provider")
	e := RegistryEntry{
		Name:       sec.Key("Name").String(),
		ID:         sec.Key("ID").String(),
		DBusName:   sec.Key("DBusName").String(),
		ObjectPath: sec.Key("ObjectPath").String(),
		Priority:   50,
	}
	if p, err := sec.Key("Priority").Int(); err == nil {
		e.Priority = p
	}
	for _, t := range strings.Split(sec.Key("Transports").String(), ";") {
		if t = strings.TrimSpace(t); t != "" {
			e.Transports = append(e.Transports, t)
		}
	}
	for _, a := range strings.Split(sec.Key("SupportedAlgorithms").String(), ";") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		v, err := strconv.ParseInt(a, 10, 32)
		if err == nil {
			e.SupportedAlgorithms = append(e.SupportedAlgorithms, int32(v))
		}
	}
	return e, nil
}
