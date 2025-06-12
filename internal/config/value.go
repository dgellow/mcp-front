package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ConfigValue represents a configuration value that can be either a literal value
// or a reference to be resolved at config-time ($env) or runtime ($userToken)
type ConfigValue struct {
	resolved bool
	value    string
	refType  string // "env" or "userToken"
	refValue string // env var name or token template
}

// String returns the resolved value or an error if not resolved
func (cv *ConfigValue) String() string {
	if !cv.resolved {
		panic(fmt.Sprintf("attempted to use unresolved %s reference", cv.refType))
	}
	return cv.value
}

// IsUserTokenRef returns true if this is a $userToken reference
func (cv *ConfigValue) IsUserTokenRef() bool {
	return cv.refType == "userToken"
}

// ResolveEnv resolves environment variable references
func (cv *ConfigValue) ResolveEnv() error {
	if cv.resolved || cv.refType != "env" {
		return nil
	}
	
	value := os.Getenv(cv.refValue)
	if value == "" {
		return fmt.Errorf("required environment variable %s not set", cv.refValue)
	}
	
	cv.value = value
	cv.resolved = true
	return nil
}

// ResolveUserToken resolves user token references
func (cv *ConfigValue) ResolveUserToken(userToken string) string {
	if cv.refType != "userToken" {
		return cv.String()
	}
	
	// Replace {{token}} placeholder with actual token
	return strings.ReplaceAll(cv.refValue, "{{token}}", userToken)
}

// UnmarshalJSON implements custom JSON unmarshaling
func (cv *ConfigValue) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as string first
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		cv.resolved = true
		cv.value = str
		return nil
	}
	
	// Try to unmarshal as object (reference)
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("ConfigValue must be string or reference object")
	}
	
	// Check for $env reference
	if envName, ok := obj["$env"].(string); ok {
		cv.refType = "env"
		cv.refValue = envName
		return nil
	}
	
	// Check for $userToken reference
	if template, ok := obj["$userToken"].(string); ok {
		cv.refType = "userToken"
		cv.refValue = template
		return nil
	}
	
	return fmt.Errorf("unknown reference type in ConfigValue")
}

// MarshalJSON implements custom JSON marshaling
func (cv ConfigValue) MarshalJSON() ([]byte, error) {
	if cv.resolved {
		return json.Marshal(cv.value)
	}
	
	if cv.refType == "env" {
		obj := map[string]interface{}{
			"$env": cv.refValue,
		}
		return json.Marshal(obj)
	}
	
	if cv.refType == "userToken" {
		obj := map[string]interface{}{
			"$userToken": cv.refValue,
		}
		return json.Marshal(obj)
	}
	
	return nil, fmt.Errorf("invalid ConfigValue state")
}

// ConfigValueMap represents a map of config values
type ConfigValueMap map[string]*ConfigValue

// ResolveEnv resolves all environment references in the map
func (cvm ConfigValueMap) ResolveEnv() error {
	for k, v := range cvm {
		if err := v.ResolveEnv(); err != nil {
			return fmt.Errorf("resolving %s: %w", k, err)
		}
	}
	return nil
}

// ResolveUserToken creates a regular string map with user tokens resolved
func (cvm ConfigValueMap) ResolveUserToken(userToken string) map[string]string {
	result := make(map[string]string)
	for k, v := range cvm {
		result[k] = v.ResolveUserToken(userToken)
	}
	return result
}

// UnmarshalJSON implements custom JSON unmarshaling for the map
func (cvm *ConfigValueMap) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	
	*cvm = make(ConfigValueMap)
	for k, v := range raw {
		cv := &ConfigValue{}
		if err := json.Unmarshal(v, cv); err != nil {
			return fmt.Errorf("unmarshaling %s: %w", k, err)
		}
		(*cvm)[k] = cv
	}
	return nil
}

// ConfigValueSlice represents a slice of config values  
type ConfigValueSlice []*ConfigValue

// ResolveEnv resolves all environment references in the slice
func (cvs ConfigValueSlice) ResolveEnv() error {
	for i, v := range cvs {
		if err := v.ResolveEnv(); err != nil {
			return fmt.Errorf("resolving index %d: %w", i, err)
		}
	}
	return nil
}

// ResolveUserToken creates a regular string slice with user tokens resolved
func (cvs ConfigValueSlice) ResolveUserToken(userToken string) []string {
	result := make([]string, len(cvs))
	for i, v := range cvs {
		result[i] = v.ResolveUserToken(userToken)
	}
	return result
}

// UnmarshalJSON implements custom JSON unmarshaling for the slice
func (cvs *ConfigValueSlice) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	
	*cvs = make(ConfigValueSlice, len(raw))
	for i, v := range raw {
		cv := &ConfigValue{}
		if err := json.Unmarshal(v, cv); err != nil {
			return fmt.Errorf("unmarshaling index %d: %w", i, err)
		}
		(*cvs)[i] = cv
	}
	return nil
}

// NewConfigValue creates a ConfigValue from a plain string
func NewConfigValue(value string) *ConfigValue {
	return &ConfigValue{
		resolved: true,
		value:    value,
	}
}