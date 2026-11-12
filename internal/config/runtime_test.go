package config

import "testing"

func TestRuntimeRejectsInvalidEnvironment(t *testing.T) {
	for _, name := range []string{"HTTP_READ_HEADER_TIMEOUT", "HTTP_READ_TIMEOUT", "HTTP_WRITE_TIMEOUT", "HTTP_IDLE_TIMEOUT", "HTTP_SHUTDOWN_TIMEOUT", "HTTP_MAX_BODY_BYTES"} {
		for _, value := range []string{"invalid", "0", "-1"} {
			t.Run(name+value, func(t *testing.T) {
				t.Setenv(name, value)
				if err := Load().Runtime.Validate(); err == nil {
					t.Fatal("invalid setting accepted")
				}
			})
		}
	}
	for _, value := range []string{"one,,two", "one,", "one,has space"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("GUARDRAIL_API_KEYS", value)
			if err := Load().Runtime.Validate(); err == nil {
				t.Fatal("invalid keys accepted")
			}
		})
	}
}
