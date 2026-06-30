Client binaries are embedded into this directory at dev build time.
This placeholder keeps the directory non-empty so the Go embed directive works.
In production, client binaries are downloaded from the configured binary_url.
