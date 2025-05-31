package main

import (
	"fmt"
	"strings"
)

// domainValidator handles domain validation logic
type domainValidator struct {
	allowedDomains []string
}

// newDomainValidator creates a new domain validator
func newDomainValidator(allowedDomains []string) *domainValidator {
	return &domainValidator{
		allowedDomains: allowedDomains,
	}
}

// validateDomain checks if a domain is in the allowed list
func (v *domainValidator) validateDomain(domain string) error {
	// Skip validation if no domains configured
	if len(v.allowedDomains) == 0 {
		return nil
	}

	// Domain required when allowed domains are configured
	if domain == "" {
		return fmt.Errorf("user does not belong to a hosted domain")
	}

	// Check if domain is allowed
	domain = strings.ToLower(strings.TrimSpace(domain))
	for _, allowed := range v.allowedDomains {
		if strings.ToLower(allowed) == domain {
			return nil
		}
	}

	return fmt.Errorf("domain %s is not in allowed domains", domain)
}