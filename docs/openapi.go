// Package docs holds the single source of the OpenAPI spec. It lives next to
// openapi.yaml because go:embed only reaches files at or below the package
// directory; the handlers import it instead of embedding a copy.
package docs

import _ "embed"

// OpenAPI is docs/openapi.yaml, embedded at compile time.
//
//go:embed openapi.yaml
var OpenAPI []byte
