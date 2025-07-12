package auth

import (
	"errors"
	"net/http"
	"testing"
)

func Test_GetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		header  http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "no authorization header",
			header:  http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed authorization header",
			header: http.Header{
				"Authorization": []string{"Bearer token123"},
			},
			wantKey: "",
			wantErr: ErrMalformedAuthHeader,
		},
		{
			name: "valid authorization header",
			header: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			wantKey: "abc123",
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.header)

			if gotKey != tt.wantKey {
				t.Errorf("expected key: %v, got: %v", tt.wantKey, gotKey)
			}

			if (gotErr != nil && tt.wantErr == nil) || (gotErr == nil && tt.wantErr != nil) {
				t.Errorf("expected error: %v, got: %v", tt.wantErr, gotErr)
			} else if !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("expected error: %v, got: %v", tt.wantErr, gotErr)
			}
		})
	}
}
