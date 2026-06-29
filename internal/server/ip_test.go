package server

import (
	"testing"
)

func TestParseAllowedIPs(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"single_ip", "127.0.0.1", []string{"127.0.0.1/32"}, false},
		{"single_cidr", "192.168.1.0/24", []string{"192.168.1.0/24"}, false},
		{"multiple", "127.0.0.1, 10.0.0.0/8", []string{"127.0.0.1/32", "10.0.0.0/8"}, false},
		{"invalid_ip", "not-an-ip", nil, true},
		{"invalid_cidr", "192.168.1.0/33", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAllowedIPs(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAllowedIPs(%q) error = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseAllowedIPs(%q) = %v, want %v", tt.raw, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("parseAllowedIPs(%q)[%d] = %q, want %q", tt.raw, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestIPAllowed(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		allowedIPs []string
		want       bool
	}{
		{"empty_list", "1.2.3.4", nil, true},
		{"empty_list_empty", "1.2.3.4", []string{}, true},
		{"match_exact", "192.168.1.100", []string{"192.168.1.100/32"}, true},
		{"match_cidr", "192.168.1.100", []string{"192.168.1.0/24"}, true},
		{"no_match", "10.0.0.1", []string{"192.168.1.0/24"}, false},
		{"multiple_one_match", "10.0.0.5", []string{"192.168.1.0/24", "10.0.0.0/8"}, true},
		{"bad_client_ip", "not-an-ip", []string{"192.168.1.0/24"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipAllowed(tt.ip, tt.allowedIPs)
			if got != tt.want {
				t.Fatalf("ipAllowed(%q, %v) = %v, want %v", tt.ip, tt.allowedIPs, got, tt.want)
			}
		})
	}
}
