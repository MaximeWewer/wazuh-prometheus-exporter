// Package api is the Wazuh REST API collection backend: an HTTP client with a
// JWT token manager (cache, proactive refresh, retry-on-401) and validated TLS,
// behind an APIClient interface. It is transport-only — callers (collectors)
// unmarshal the returned bytes into their own typed structs. It imports no
// Prometheus packages.
package api

// authResponse is the Wazuh `POST /security/user/authenticate` response shape:
// the JWT is wrapped under `data.token`.
type authResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
}
