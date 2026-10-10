package config

import (
	"fmt"

	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
)

// DecodeSettings maps a module's opaque settings block onto its typed config
// struct (koanf tags), converting duration strings like "30s" on the way.
// Keys the struct does not know are ignored.
func DecodeSettings(settings map[string]any, out any) error {
	return decodeSettings(settings, out, false)
}

// DecodeSettingsStrict is DecodeSettings for modules where a misspelt key is
// a silent misconfiguration rather than a harmless leftover: an LLM option
// the decoder drops leaves the model on its built-in default (temperature 1,
// presence_penalty 1.5) while the operator believes it pinned. Unknown keys
// fail the decoding, so the process refuses to start.
func DecodeSettingsStrict(settings map[string]any, out any) error {
	return decodeSettings(settings, out, true)
}

func decodeSettings(settings map[string]any, out any, strict bool) error {
	k := koanf.New(".")
	if err := k.Load(confmap.Provider(settings, "."), nil); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	uc := koanf.UnmarshalConf{Tag: "koanf", DecoderConfig: &mapstructure.DecoderConfig{
		DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
		Result:           out,
		WeaklyTypedInput: true,
		ErrorUnused:      strict,
	}}
	if err := k.UnmarshalWithConf("", out, uc); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}
	return nil
}
