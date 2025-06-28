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
