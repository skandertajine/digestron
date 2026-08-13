package config

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
)

// DecodeSettings maps a module's opaque settings block onto its typed config
// struct (koanf tags), converting duration strings like "30s" on the way.
func DecodeSettings(settings map[string]any, out any) error {
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(settings, "."), nil); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	uc := koanf.UnmarshalConf{Tag: "koanf", DecoderConfig: &mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
		Result:           out,
		WeaklyTypedInput: true,
	}}
	if err := k.UnmarshalWithConf("", out, uc); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	return nil
}
