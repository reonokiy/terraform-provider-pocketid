package client_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Trozz/terraform-provider-pocketid/internal/client"
)

func TestClient_APIs(t *testing.T) {
	description := "Read telemetry"
	expected := &client.API{
		ID:       "api-1",
		Name:     "Telemetry ingest",
		Resource: "https://ingest.example.com",
		Permissions: []client.APIPermission{{
			ID:          "permission-1",
			Key:         "telemetry.write",
			Name:        "Write telemetry",
			Description: &description,
		}},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-token", r.Header.Get("X-API-KEY"))
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/apis":
			var request client.APICreateRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			assert.Equal(t, "Telemetry ingest", request.Name)
			assert.Equal(t, "https://ingest.example.com", request.Resource)
			require.NoError(t, json.NewEncoder(w).Encode(expected))
		case r.Method == http.MethodGet && r.URL.Path == "/api/apis/api-1":
			require.NoError(t, json.NewEncoder(w).Encode(expected))
		case r.Method == http.MethodPut && r.URL.Path == "/api/apis/api-1":
			var request client.APIUpdateRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			assert.Equal(t, "Renamed telemetry ingest", request.Name)
			expected.Name = request.Name
			require.NoError(t, json.NewEncoder(w).Encode(expected))
		case r.Method == http.MethodPut && r.URL.Path == "/api/apis/api-1/permissions":
			var request client.APIUpdatePermissionsRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			assert.Len(t, request.Permissions, 1)
			assert.Equal(t, "telemetry.write", request.Permissions[0].Key)
			require.NoError(t, json.NewEncoder(w).Encode(expected))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/apis/api-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	c, err := client.NewClient(server.URL, "test-token", false, 30)
	require.NoError(t, err)

	created, err := c.CreateAPI(&client.APICreateRequest{Name: "Telemetry ingest", Resource: "https://ingest.example.com"})
	require.NoError(t, err)
	assert.Equal(t, expected, created)

	got, err := c.GetAPI("api-1")
	require.NoError(t, err)
	assert.Equal(t, expected, got)

	updated, err := c.UpdateAPI("api-1", &client.APIUpdateRequest{Name: "Renamed telemetry ingest"})
	require.NoError(t, err)
	assert.Equal(t, expected, updated)

	permissions, err := c.UpdateAPIPermissions("api-1", []client.APIPermissionInput{{Key: "telemetry.write", Name: "Write telemetry", Description: &description}})
	require.NoError(t, err)
	assert.Equal(t, expected, permissions)

	require.NoError(t, c.DeleteAPI("api-1"))
}

func TestClient_APIClientAccess(t *testing.T) {
	expected := &client.APIClientGrant{
		ClientAccess:        true,
		ClientPermissionIDs: []string{"permission-1"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-token", r.Header.Get("X-API-KEY"))
		w.Header().Set("Content-Type", "application/json")

		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/api/apis/api-1/clients/client-1":
			var request client.APIClientGrant
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			assert.False(t, request.UserDelegatedAccess)
			assert.False(t, request.ClientAccess)
			assert.Empty(t, request.UserDelegatedPermissionIDs)
			assert.Empty(t, request.ClientPermissionIDs)
			require.NoError(t, json.NewEncoder(w).Encode(expected))
		case r.Method == http.MethodGet && r.URL.Path == "/api/api-access/client-1/apis":
			require.NoError(t, json.NewEncoder(w).Encode([]client.ClientAPIGrant{{
				API:            client.API{ID: "api-1", Name: "Telemetry ingest", Resource: "https://ingest.example.com"},
				APIClientGrant: *expected,
			}}))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/apis/api-1/clients/client-1":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	c, err := client.NewClient(server.URL, "test-token", false, 30)
	require.NoError(t, err)

	applied, err := c.UpdateAPIClientAccess("api-1", "client-1", &client.APIClientGrant{})
	require.NoError(t, err)
	assert.Equal(t, expected, applied)

	grants, err := c.ListClientAPIs("client-1")
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, "api-1", grants[0].API.ID)
	assert.Equal(t, expected.ClientPermissionIDs, grants[0].ClientPermissionIDs)

	require.NoError(t, c.DeleteAPIClientAccess("api-1", "client-1"))
}
