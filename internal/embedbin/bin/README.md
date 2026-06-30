Client binaries are embedded into this directory at dev build time.
The server binary is also copied here during development builds.
This placeholder keeps the directory non-empty so the Go embed directive works.
In production, client binaries are downloaded from the configured binary_url.
