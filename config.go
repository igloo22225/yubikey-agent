package main

import (
	"fmt"
	"os"

	"github.com/go-piv/piv-go/v2/piv"
	"gopkg.in/yaml.v3"
)

var slotNames = map[string]piv.Slot{
	"Authentication":     piv.SlotAuthentication,
	"Signature":          piv.SlotSignature,
	"KeyManagement":      piv.SlotKeyManagement,
	"CardAuthentication": piv.SlotCardAuthentication,
}

type slotConfig struct {
	Slot piv.Slot
	Name string
}

type configFile struct {
	Keyslots []map[string]*string `yaml:"keyslots"`
}

func loadConfig(path string) ([]slotConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg []configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if len(cfg) == 0 || len(cfg[0].Keyslots) == 0 {
		return defaultSlotConfig(), nil
	}

	var slots []slotConfig
	seen := make(map[string]bool)
	for _, entry := range cfg[0].Keyslots {
		for name, socketName := range entry {
			slot, ok := slotNames[name]
			if !ok {
				return nil, fmt.Errorf("unknown slot name %q", name)
			}
			if socketName == nil {
				continue // null value means skip this slot
			}
			if seen[*socketName] {
				return nil, fmt.Errorf("duplicate socket name %q", *socketName)
			}
			seen[*socketName] = true
			slots = append(slots, slotConfig{Slot: slot, Name: *socketName})
		}
	}

	if len(slots) == 0 {
		return defaultSlotConfig(), nil
	}
	return slots, nil
}

func defaultSlotConfig() []slotConfig {
	return []slotConfig{{Slot: piv.SlotAuthentication, Name: ""}}
}

func socketPathForSlot(basePath string, sc slotConfig) string {
	if sc.Name == "" {
		return basePath
	}
	return basePath + "-" + sc.Name
}

func slotDisplayName(sc slotConfig) string {
	for name, s := range slotNames {
		if s == sc.Slot {
			if sc.Name != "" {
				return fmt.Sprintf("%s / %s", name, sc.Name)
			}
			return name
		}
	}
	return sc.Slot.String()
}

func slotForSetup(name string) (slotConfig, error) {
	slot, ok := slotNames[name]
	if !ok {
		return slotConfig{}, fmt.Errorf("unknown slot name %q", name)
	}
	return slotConfig{Slot: slot, Name: name}, nil
}
