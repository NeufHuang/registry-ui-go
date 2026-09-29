package config

import "testing"

// TestExternalURL covers the EXTERNAL_URL override used for the OCI token
// realm: it must be an absolute http(s) URL and keep no trailing slash.
func TestExternalURL(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: ""},
		{in: "https://registry.example.com:9999/", want: "https://registry.example.com:9999"},
		{in: " http://ui.internal:8080 ", want: "http://ui.internal:8080"},
		{in: "registry.example.com:9999", wantErr: true},
		{in: "ftp://registry.example.com", wantErr: true},
		{in: "https://", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Setenv("EXTERNAL_URL", tc.in)
			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("EXTERNAL_URL=%q: expected an error", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("EXTERNAL_URL=%q: %v", tc.in, err)
			}
			if cfg.ExternalURL != tc.want {
				t.Errorf("EXTERNAL_URL=%q: got %q, want %q", tc.in, cfg.ExternalURL, tc.want)
			}
		})
	}
}
