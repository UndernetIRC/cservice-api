// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

import "testing"

func TestValidator_Translation(t *testing.T) {
	type testStruct struct {
		Field string `validate:"required"`
	}
	v := NewValidator()
	err := v.Validate(testStruct{})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != "Field is a required field" {
		t.Fatalf("expected error to be 'Field is a required field', got '%s'", err.Error())
	}
}

func TestValidator_IRCUsername(t *testing.T) {
	type testStruct struct {
		Username string `validate:"ircusername"`
	}

	v := NewValidator()

	tests := []struct {
		name      string
		username  string
		shouldErr bool
	}{
		{"valid username", "testuser", false},
		{"valid with numbers", "test123", false},
		{"valid mixed case", "TestUser", false},
		{"with underscore", "test_user", true},
		{"with hyphen", "test-user", true},
		{"with brackets", "test[123]", true},
		{"starts with underscore", "_testuser", true},
		{"starts with hyphen", "-testuser", true},
		{"invalid characters", "test@user", true},
		{"empty string", "", false}, // required validator handles this
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(testStruct{Username: tt.username})
			if tt.shouldErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidator_NoControlChars(t *testing.T) {
	type testStruct struct {
		Text string `validate:"nocontrolchars"`
	}

	v := NewValidator()

	tests := []struct {
		name      string
		text      string
		shouldErr bool
	}{
		{"normal text", "This is normal text", false},
		{"with newline", "Text with\nnewline", false},
		{"with tab", "Text with\ttab", false},
		{"with control char", "Text with\x00null", true},
		{"with control char 2", "Text with\x01control", true},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(testStruct{Text: tt.text})
			if tt.shouldErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidator_AlphanumToken(t *testing.T) {
	type testStruct struct {
		Token string `validate:"alphanumtoken"`
	}

	v := NewValidator()

	tests := []struct {
		name      string
		token     string
		shouldErr bool
	}{
		{"alphanumeric", "abc123DEF", false},
		{"only letters", "abcDEF", false},
		{"only numbers", "123456", false},
		{"with hyphen", "abc-123", true},
		{"with underscore", "abc_123", true},
		{"with special chars", "abc@123", true},
		{"empty string", "", false}, // required validator handles this
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(testStruct{Token: tt.token})
			if tt.shouldErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidator_MeaningfulContent(t *testing.T) {
	type testStruct struct {
		Content string `validate:"meaningful"`
	}

	v := NewValidator()

	tests := []struct {
		name      string
		content   string
		shouldErr bool
	}{
		{"meaningful content", "Taking a break for personal reasons", false},
		{"meaningful content 2", "Need to transfer management temporarily", false},
		{"single word", "break", true},
		{"placeholder text", "test", true},
		{"placeholder text 2", "insert reason here", true},
		{"repeated characters", "aaaaaaaaaaa", true},
		{"mostly repeated", "xxxxxxxxxx y", true},
		{"empty string", "", false}, // required validator handles this
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(testStruct{Content: tt.content})
			if tt.shouldErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidator_CIDR(t *testing.T) {
	type testStruct struct {
		CIDR string `validate:"cidr"`
	}

	v := NewValidator()

	tests := []struct {
		name      string
		cidr      string
		shouldErr bool
	}{
		{"valid IPv4 CIDR", "192.168.1.0/24", false},
		{"valid IPv4 single host", "192.168.1.1/32", false},
		{"valid IPv6 CIDR", "2001:db8::/32", false},
		{"valid IPv6 single host", "2001:db8::1/128", false},
		{"valid localhost IPv4", "127.0.0.0/8", false},
		{"valid localhost IPv6", "::1/128", false},
		{"invalid - no prefix", "192.168.1.0", true},
		{"invalid - bad IP", "256.256.256.256/24", true},
		{"invalid - bad prefix", "192.168.1.0/33", true},
		{"invalid - not CIDR", "not-a-cidr", true},
		{"empty string", "", false}, // omitempty or required handles this
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(testStruct{CIDR: tt.cidr})
			if tt.shouldErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidator_CIDRSlice(t *testing.T) {
	type testStruct struct {
		CIDRs []string `validate:"dive,cidr"`
	}

	v := NewValidator()

	tests := []struct {
		name      string
		cidrs     []string
		shouldErr bool
	}{
		{"valid slice", []string{"192.168.1.0/24", "10.0.0.0/8"}, false},
		{"empty slice", []string{}, false},
		{"nil slice", nil, false},
		{"one invalid", []string{"192.168.1.0/24", "invalid"}, true},
		{"all invalid", []string{"invalid1", "invalid2"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Validate(testStruct{CIDRs: tt.cidrs})
			if tt.shouldErr && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.shouldErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
