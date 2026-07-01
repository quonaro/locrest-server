package config

// Redacted returns a shallow copy of the configuration with sensitive values
// replaced by "[redacted]". The original config is not modified.
func (c *ServerConfig) Redacted() *ServerConfig {
	if c == nil {
		return nil
	}
	out := *c
	if out.TLS.Key != "" {
		out.TLS.Key = "[redacted]"
	}
	if out.TLS.CertMagic.APIToken != "" {
		out.TLS.CertMagic.APIToken = "[redacted]"
	}
	if out.TLS.CertMagic.AccessKeyID != "" {
		out.TLS.CertMagic.AccessKeyID = "[redacted]"
	}
	if out.TLS.CertMagic.SecretAccessKey != "" {
		out.TLS.CertMagic.SecretAccessKey = "[redacted]"
	}
	return &out
}
