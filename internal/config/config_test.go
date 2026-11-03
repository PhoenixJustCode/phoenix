package config

import "testing"

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr bool
	}{
		{
			name:    "database url is required",
			env:     map[string]string{},
			wantErr: true,
		},
		{
			name: "defaults",
			env:  map[string]string{"DATABASE_URL": "postgres://db"},
			want: Config{
				DatabaseURL: "postgres://db",
				ListenAddr:  defaultListenAddr,
				GeoBaseURL:  defaultGeoBaseURL,
			},
		},
		{
			name: "overrides",
			env: map[string]string{
				"DATABASE_URL": "postgres://db",
				"LISTEN_ADDR":  ":9000",
				"GEO_BASE_URL": "http://geo",
			},
			want: Config{DatabaseURL: "postgres://db", ListenAddr: ":9000", GeoBaseURL: "http://geo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(func(k string) string { return tt.env[k] })
			if (err != nil) != tt.wantErr {
				t.Fatalf("Load() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
