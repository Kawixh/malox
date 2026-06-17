package node

import "testing"

func TestNpmPURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "left-pad", version: "1.3.0", want: "pkg:npm/left-pad@1.3.0"},
		{name: "@scope/pkg", version: "1.2.3", want: "pkg:npm/%40scope/pkg@1.2.3"},
		{name: "left-pad", version: "^1.3.0", want: ""},
		{name: "left-pad", version: "npm:other@1.3.0", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name+"/"+tt.version, func(t *testing.T) {
			if got := NpmPURL(tt.name, tt.version); got != tt.want {
				t.Fatalf("NpmPURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
