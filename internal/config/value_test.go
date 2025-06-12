package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestConfigValue_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		wantType string
		wantVal  string
	}{
		{
			name:     "plain string",
			json:     `"hello world"`,
			wantType: "",
			wantVal:  "hello world",
		},
		{
			name:     "env ref",
			json:     `{"$env": "MY_VAR"}`,
			wantType: "env",
			wantVal:  "",
		},
		{
			name:     "user token ref",
			json:     `{"$userToken": "Bearer {{token}}"}`,
			wantType: "userToken",
			wantVal:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cv ConfigValue
			err := json.Unmarshal([]byte(tt.json), &cv)
			if err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}

			if tt.wantType == "" {
				// Plain value
				if !cv.resolved {
					t.Errorf("expected resolved = true")
				}
				if cv.value != tt.wantVal {
					t.Errorf("value = %v, want %v", cv.value, tt.wantVal)
				}
			} else {
				// Reference
				if cv.resolved {
					t.Errorf("expected resolved = false")
				}
				if cv.refType != tt.wantType {
					t.Errorf("refType = %v, want %v", cv.refType, tt.wantType)
				}
			}
		})
	}
}

func TestConfigValue_UnmarshalJSON_Errors(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{
			name:    "invalid json",
			json:    `{invalid}`,
			wantErr: "invalid character",
		},
		{
			name:    "unknown reference type",
			json:    `{"$unknown": "value"}`,
			wantErr: "unknown reference type",
		},
		{
			name:    "number instead of string",
			json:    `123`,
			wantErr: "ConfigValue must be string or reference object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cv ConfigValue
			err := json.Unmarshal([]byte(tt.json), &cv)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !containsString(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValue_ResolveEnv(t *testing.T) {
	// Set test env var
	os.Setenv("TEST_VAR", "test_value")
	defer os.Unsetenv("TEST_VAR")

	tests := []struct {
		name    string
		json    string
		wantVal string
		wantErr bool
	}{
		{
			name:    "env var exists",
			json:    `{"$env": "TEST_VAR"}`,
			wantVal: "test_value",
		},
		{
			name:    "env var missing",
			json:    `{"$env": "MISSING_VAR"}`,
			wantErr: true,
		},
		{
			name:    "already resolved",
			json:    `"plain value"`,
			wantVal: "plain value",
		},
		{
			name:    "user token ref not resolved by env",
			json:    `{"$userToken": "Bearer {{token}}"}`,
			wantVal: "",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cv ConfigValue
			json.Unmarshal([]byte(tt.json), &cv)
			
			err := cv.ResolveEnv()
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveEnv() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr && cv.resolved && cv.String() != tt.wantVal {
				t.Errorf("String() = %v, want %v", cv.String(), tt.wantVal)
			}
		})
	}
}

func TestConfigValue_ResolveUserToken(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		userToken string
		want      string
	}{
		{
			name:      "simple token substitution",
			json:      `{"$userToken": "Bearer {{token}}"}`,
			userToken: "secret123",
			want:      "Bearer secret123",
		},
		{
			name:      "json template",
			json:      `{"$userToken": "{\"Authorization\": \"Bearer {{token}}\"}"}`,
			userToken: "secret456",
			want:      `{"Authorization": "Bearer secret456"}`,
		},
		{
			name:      "plain string passthrough",
			json:      `"static value"`,
			userToken: "ignored",
			want:      "static value",
		},
		{
			name:      "env ref passthrough after resolution",
			json:      `{"$env": "TEST_VAR"}`,
			userToken: "ignored",
			want:      "test_value",
		},
	}

	// Set test env var for one test
	os.Setenv("TEST_VAR", "test_value")
	defer os.Unsetenv("TEST_VAR")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cv ConfigValue
			json.Unmarshal([]byte(tt.json), &cv)
			
			// Resolve env if needed
			if cv.refType == "env" {
				cv.ResolveEnv()
			}
			
			got := cv.ResolveUserToken(tt.userToken)
			if got != tt.want {
				t.Errorf("ResolveUserToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfigValue_String_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("String() did not panic on unresolved value")
		}
	}()
	
	cv := ConfigValue{
		resolved: false,
		refType:  "env",
		refValue: "SOME_VAR",
	}
	_ = cv.String()
}

func TestConfigValue_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		cv   ConfigValue
		want string
	}{
		{
			name: "resolved string",
			cv: ConfigValue{
				resolved: true,
				value:    "hello world",
			},
			want: `"hello world"`,
		},
		{
			name: "env ref",
			cv: ConfigValue{
				refType:  "env",
				refValue: "MY_VAR",
			},
			want: `{"$env":"MY_VAR"}`,
		},
		{
			name: "user token ref",
			cv: ConfigValue{
				refType:  "userToken",
				refValue: "Bearer {{token}}",
			},
			want: `{"$userToken":"Bearer {{token}}"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.cv)
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("MarshalJSON() = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestConfigValueMap_ResolveEnv(t *testing.T) {
	os.Setenv("VAR1", "value1")
	os.Setenv("VAR2", "value2")
	defer func() {
		os.Unsetenv("VAR1")
		os.Unsetenv("VAR2")
	}()

	cvm := ConfigValueMap{
		"key1": &ConfigValue{refType: "env", refValue: "VAR1"},
		"key2": &ConfigValue{refType: "env", refValue: "VAR2"},
		"key3": &ConfigValue{resolved: true, value: "static"},
	}

	err := cvm.ResolveEnv()
	if err != nil {
		t.Fatalf("ResolveEnv() error = %v", err)
	}

	if cvm["key1"].String() != "value1" {
		t.Errorf("key1 = %v, want value1", cvm["key1"].String())
	}
	if cvm["key2"].String() != "value2" {
		t.Errorf("key2 = %v, want value2", cvm["key2"].String())
	}
	if cvm["key3"].String() != "static" {
		t.Errorf("key3 = %v, want static", cvm["key3"].String())
	}
}

func TestConfigValueMap_ResolveUserToken(t *testing.T) {
	cvm := ConfigValueMap{
		"static": &ConfigValue{resolved: true, value: "plain"},
		"token1": &ConfigValue{refType: "userToken", refValue: "Bearer {{token}}"},
		"token2": &ConfigValue{refType: "userToken", refValue: "Token: {{token}}"},
	}

	result := cvm.ResolveUserToken("secret123")
	
	if result["static"] != "plain" {
		t.Errorf("static = %v, want plain", result["static"])
	}
	if result["token1"] != "Bearer secret123" {
		t.Errorf("token1 = %v, want Bearer secret123", result["token1"])
	}
	if result["token2"] != "Token: secret123" {
		t.Errorf("token2 = %v, want Token: secret123", result["token2"])
	}
}

func TestConfigValueSlice_ResolveEnv(t *testing.T) {
	os.Setenv("ARG1", "value1")
	os.Setenv("ARG2", "value2")
	defer func() {
		os.Unsetenv("ARG1")
		os.Unsetenv("ARG2")
	}()

	cvs := ConfigValueSlice{
		&ConfigValue{resolved: true, value: "static"},
		&ConfigValue{refType: "env", refValue: "ARG1"},
		&ConfigValue{refType: "env", refValue: "ARG2"},
	}

	err := cvs.ResolveEnv()
	if err != nil {
		t.Fatalf("ResolveEnv() error = %v", err)
	}

	if cvs[0].String() != "static" {
		t.Errorf("index 0 = %v, want static", cvs[0].String())
	}
	if cvs[1].String() != "value1" {
		t.Errorf("index 1 = %v, want value1", cvs[1].String())
	}
	if cvs[2].String() != "value2" {
		t.Errorf("index 2 = %v, want value2", cvs[2].String())
	}
}

func TestConfigValueSlice_ResolveUserToken(t *testing.T) {
	cvs := ConfigValueSlice{
		&ConfigValue{resolved: true, value: "arg1"},
		&ConfigValue{refType: "userToken", refValue: "--token={{token}}"},
		&ConfigValue{resolved: true, value: "arg3"},
	}

	result := cvs.ResolveUserToken("mytoken")
	
	expected := []string{"arg1", "--token=mytoken", "arg3"}
	for i, v := range result {
		if v != expected[i] {
			t.Errorf("index %d = %v, want %v", i, v, expected[i])
		}
	}
}

// Helper function
func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}