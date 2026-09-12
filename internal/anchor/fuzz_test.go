package anchor

import (
	"encoding/json"
	"testing"
)

func FuzzFromArguments(f *testing.F) {
	f.Add([]byte(`[{"name":"K","datatype":"H","value":"0000000000000000000000000000000000000000000000000000000000000001"},{"name":"C","datatype":"H","value":"0000000000000000000000000000000000000000000000000000000000000002"},{"name":"D","datatype":"U","value":1800000000},{"name":"F","datatype":"U","value":1025}]`))
	f.Add([]byte("{}"))
	f.Add([]byte("[]"))
	f.Add([]byte("null"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		var args Arguments
		if err := json.Unmarshal(raw, &args); err != nil {
			t.Skip()
		}
		_, _ = FromArguments(args)
	})
}
