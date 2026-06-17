package node

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

func yamlUnmarshal(data []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	return decoder.Decode(target)
}
