package input

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type StringOrStringList []string

func (s *StringOrStringList) UnmarshalJSON(b []byte) error {
	xs := []string{}
	switch {
	case bytes.HasPrefix(b, []byte("[")):
		if err := json.Unmarshal(b, &xs); err != nil {
			return err
		}
	case bytes.HasPrefix(b, []byte(`"`)):
		var t string
		if err := json.Unmarshal(b, &t); err != nil {
			return err
		}
		xs = []string{t}
	default:
		return fmt.Errorf("unexpected json value: %v", b)
	}
	*s = StringOrStringList(xs)
	return nil
}
