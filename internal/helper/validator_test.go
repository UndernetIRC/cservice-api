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
