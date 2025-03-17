package main

import (
	"testing"
)

func TestUnescapeSSID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple ASCII string",
			input:    "HomeNetwork",
			expected: "HomeNetwork",
		},
		{
			name:     "String with single-byte escape",
			input:    "Caf\\xc3\\xa9",
			expected: "Café",
		},
		{
			name:     "String with running emoji (4 bytes)",
			input:    "Run\\xf0\\x9f\\x8f\\x83",
			expected: "Run🏃",
		},
		{
			name:     "String with multiple emoji",
			input:    "\\xf0\\x9f\\x8f\\x83\\xf0\\x9f\\x8c\\x9f",
			expected: "🏃🌟",
		},
		{
			name:     "String with emoji and regular text",
			input:    "My\\xf0\\x9f\\x8f\\x83Network\\xf0\\x9f\\x8c\\x9f",
			expected: "My🏃Network🌟",
		},
		{
			name:     "String with invalid escape sequence",
			input:    "Test\\xZZ",
			expected: "Test\\xZZ", // Note the escaped backslash
		},
		{
			name:     "Mixed valid and invalid escape sequences",
			input:    "\\xf0\\x9f\\x8f\\x83\\xZZ",
			expected: "🏃\\xZZ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := unescapeSSID(tt.input)
			if result != tt.expected {
				t.Errorf("unescapeSSID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
