package internal

import (
	"context"
	"fmt"
	"github.com/Joffref/opa-middleware/config"
	"github.com/open-policy-agent/opa/rego"
	assert "github.com/stretchr/testify/require"
	"net/http"
	"testing"
	"time"
)

func TestQueryPolicy(t *testing.T) {
	policy := `
package policy

default allow = false

allow {
	input.path = "/api/v1/users"
	input.method = "GET"
}`

	type args struct {
		r    *http.Request
		cfg  *config.Config
		bind map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "query policy should return true",
			args: args{
				r: &http.Request{},
				cfg: &config.Config{
					Policy:  policy,
					Query:   "data.policy.allow",
					Timeout: 10 * time.Second,
				},
				bind: map[string]interface{}{
					"path":   "/api/v1/users",
					"method": "GET",
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "query policy should return false",
			args: args{
				r: &http.Request{},
				cfg: &config.Config{
					Policy:  policy,
					Query:   "data.policy.allow",
					Timeout: 10 * time.Second,
				},
				bind: map[string]interface{}{
					"path":   "/api/v1/users",
					"method": "POST",
				},
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := QueryPolicy(tt.args.r, tt.args.cfg, tt.args.bind)
			if (err != nil) != tt.wantErr {
				t.Errorf("QueryPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("QueryPolicy() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryURL(t *testing.T) {
	_ = `
package policy

default allow = false

allow {
	input.path = "/api/v1/users"
	input.method = "GET"
}`
	type args struct {
		r    *http.Request
		cfg  *config.Config
		bind map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		/*
			{
				name: "query url should return true",
				args: args{
					r: &http.Request{
						URL: &url.URL{
							Path: "/api/v1/users",
						},
					},
					cfg: &config.Config{
						URL:   "data.url.path",
						Query: "data.url.path == \"/api/v1/users\"",
					},
				},
			},
		*/
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := QueryURL(tt.args.r, tt.args.cfg, tt.args.bind)
			if (err != nil) != tt.wantErr {
				t.Errorf("QueryURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("QueryURL() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQuery(t *testing.T) {
	input := map[string]interface{}{
		"role": "admin",
		"path": "/admin/api1",
		// Add any other relevant input data
	}
	allowed, err := evaluatePolicy(input)
	assert.Truef(t, allowed, "allowed: %v err: %v", allowed, err)

	input = map[string]interface{}{
		"role": "member",
		"path": "/admin/api1",
		// Add any other relevant input data
	}
	allowed, err = evaluatePolicy(input)
	assert.Falsef(t, allowed, "input: %v", input)

	input = map[string]interface{}{
		"role": "member",
		"path": "/services/api1",
		// Add any other relevant input data
	}
	allowed, err = evaluatePolicy(input)
	assert.Truef(t, allowed, "input: %v", input)
}

func evaluatePolicy(input interface{}) (bool, error) {
	policy := `
package authz
default allow = true

isAdminRole = {"admin"}

onlyAdminAPI = {
    "/admin/api1",
    "/admin/api2",
    "/admin/api3"
}

allow {
	isAdminRole[input.role]
	onlyAdminAPI[input.path]
}

allow {
	not isAdminRole[input.role]
	not onlyAdminAPI[input.path]
}

`

	// Create a new Rego module using the policy string
	module, err := rego.New(rego.Query("allow = data.authz.allow"),
		rego.Module("policy.rego", policy),
	).PrepareForEval(context.Background())
	if err != nil {
		fmt.Printf("Failed to load Rego policy: %v\n", err)
		return false, err
	}

	// Construct the input data for policy evaluation

	// Evaluate the query against the loaded policy
	results, err := module.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		fmt.Printf("Failed to evaluate query: %v\n", err)
		return false, err
	}

	// Extract the result of the query
	allow, ok := results[0].Bindings["allow"].(bool)
	if !ok {
		fmt.Println("Invalid result")
		return false, err
	}

	fmt.Println("Allow:", allow)
	return allow, nil
}
