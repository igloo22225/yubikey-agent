package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/go-piv/piv-go/v2/piv"
	"gopkg.in/yaml.v3"
)

type SlotPurpose string

const (
	PurposeSignature  SlotPurpose = "signature"
	PurposeEncryption SlotPurpose = "encryption"
)

var slotNames = map[string]piv.Slot{
	"Authentication":     piv.SlotAuthentication,
	"Signature":          piv.SlotSignature,
	"KeyManagement":      piv.SlotKeyManagement,
	"CardAuthentication": piv.SlotCardAuthentication,
}

func parseRetiredSlot(name string) (piv.Slot, bool) {
	id, err := strconv.ParseUint(name, 16, 32)
	if err != nil {
		return piv.Slot{}, false
	}
	return piv.RetiredKeyManagementSlot(uint32(id))
}

func lookupSlot(name string) (piv.Slot, bool) {
	if slot, ok := slotNames[name]; ok {
		return slot, true
	}
	return parseRetiredSlot(name)
}

type slotConfig struct {
	Slot    piv.Slot
	Name    string
	Purpose SlotPurpose
}

type configFile struct {
	Keyslots    []map[string]yaml.Node `yaml:"keyslots"`
	Attestation bool                   `yaml:"attestation"`
}

type parsedConfig struct {
	Slots       []slotConfig
	Attestation bool
}

func parseSlotProperties(node *yaml.Node) (*slotConfig, error) {
	if node == nil || node.Tag == "!!null" || (node.Kind == yaml.ScalarNode && node.Value == "") {
		return nil, nil
	}

	if node.Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("expected a string, null, or list of properties, got YAML kind %d", node.Kind)
	}

	sc := &slotConfig{Purpose: PurposeSignature}
	for _, item := range node.Content {
		if item.Kind != yaml.MappingNode || len(item.Content) != 2 {
			return nil, fmt.Errorf("expected a single-key mapping in slot property list")
		}
		key := item.Content[0].Value
		val := item.Content[1].Value
		switch key {
		case "name":
			sc.Name = val
		case "purpose":
			switch SlotPurpose(val) {
			case PurposeSignature, PurposeEncryption:
				sc.Purpose = SlotPurpose(val)
			default:
				return nil, fmt.Errorf("unknown purpose %q (must be %q or %q)", val, PurposeSignature, PurposeEncryption)
			}
		default:
			return nil, fmt.Errorf("unknown slot property %q", key)
		}
	}
	return sc, nil
}

func loadConfig(path string) (parsedConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return parsedConfig{}, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg []configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return parsedConfig{}, fmt.Errorf("failed to parse config file: %w", err)
	}

	if len(cfg) == 0 {
		return parsedConfig{Slots: defaultSlotConfig(), Attestation: false}, nil
	}

	// The config file is a YAML list. Each field (keyslots, attestation)
	// may appear in any list item, or may be absent entirely. Merge across
	// all items so that the order and grouping don't matter.
	var allKeyslots []map[string]yaml.Node
	attestation := false
	for _, item := range cfg {
		if len(item.Keyslots) > 0 {
			allKeyslots = append(allKeyslots, item.Keyslots...)
		}
		if item.Attestation {
			attestation = true
		}
	}

	if len(allKeyslots) == 0 {
		return parsedConfig{Slots: defaultSlotConfig(), Attestation: attestation}, nil
	}

	var slots []slotConfig
	seen := make(map[string]bool)
	for _, entry := range allKeyslots {
		for name, node := range entry {
			slot, ok := lookupSlot(name)
			if !ok {
				return parsedConfig{}, fmt.Errorf("unknown slot name %q (use a named slot like Authentication, Signature, KeyManagement, CardAuthentication, or a retired slot hex ID 82-95)", name)
			}
			sc, err := parseSlotProperties(&node)
			if err != nil {
				return parsedConfig{}, fmt.Errorf("slot %q: %w", name, err)
			}
			if sc == nil {
				continue // null value means skip this slot
			}
			sc.Slot = slot
			if seen[sc.Name] {
				return parsedConfig{}, fmt.Errorf("duplicate socket name %q", sc.Name)
			}
			seen[sc.Name] = true
			slots = append(slots, *sc)
		}
	}

	if len(slots) == 0 {
		slots = defaultSlotConfig()
	}
	return parsedConfig{Slots: slots, Attestation: attestation}, nil
}

func defaultSlotConfig() []slotConfig {
	return []slotConfig{{Slot: piv.SlotAuthentication, Name: "", Purpose: PurposeSignature}}
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
	hex := sc.Slot.String()
	if sc.Name != "" {
		return fmt.Sprintf("Retired(%s) / %s", hex, sc.Name)
	}
	return fmt.Sprintf("Retired(%s)", hex)
}

func slotForSetup(name string) (slotConfig, error) {
	slot, ok := lookupSlot(name)
	if !ok {
		return slotConfig{}, fmt.Errorf("unknown slot name %q (use a named slot like Authentication, Signature, KeyManagement, CardAuthentication, or a retired slot hex ID 82-95)", name)
	}
	return slotConfig{Slot: slot, Name: name, Purpose: PurposeSignature}, nil
}
