package input

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestStringOrStringListUnmarshalJSON(t *testing.T) {
	t.Parallel()

	testcases := []struct {
		name  string
		input string
		want  StringOrStringList
	}{
		{
			name:  "Unmarshal string",
			input: `"foo"`,
			want:  StringOrStringList{"foo"},
		},
		{
			name:  "Unmarshal string list",
			input: `["foo","bar"]`,
			want:  StringOrStringList{"foo", "bar"},
		},
	}
	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dst := StringOrStringList{}
			if err := json.Unmarshal([]byte(tt.input), &dst); err != nil {
				t.Fatalf("Error unmarshaling JSON: %v", err)
			}

			if !reflect.DeepEqual(tt.want, dst) {
				t.Errorf("Result mismatch\n\twant: %s\n\tgot: %s", tt.want, dst)
			}
		})
	}
}
