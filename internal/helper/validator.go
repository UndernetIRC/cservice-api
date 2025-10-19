// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package helper provides helper functions
package helper

import (
	"fmt"
	"log"
	"net"
	"reflect"
	"regexp"
	"strings"
	"unicode"

	"github.com/go-playground/locales/en_US"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	enTranslation "github.com/go-playground/validator/v10/translations/en"
)

// Validator is a wrapper around the validator package
type Validator struct {
	validator *validator.Validate
	transEN   ut.Translator
}

// NewValidator returns a new Validator
func NewValidator() *Validator {
	english := en_US.New()
	uni := ut.New(english, english)
	transEN, found := uni.GetTranslator("en_US")
	if !found {
		log.Fatal("translator not found")
	}
	validate := validator.New()

	// Override the default tag name by using the json tag
	validate.RegisterTagNameFunc(func(field reflect.StructField) string {
		return field.Tag.Get("json")
	})

	// Register default translations
	if err := enTranslation.RegisterDefaultTranslations(validate, transEN); err != nil {
		log.Fatal(err)
	}

	// Register custom validators
	registerCustomValidators(validate, transEN)

	return &Validator{
		validator: validate,
		transEN:   transEN,
	}
}

// Validate validates a struct based on the tags
func (v *Validator) Validate(i interface{}) error {
	err := v.validator.Struct(i)
	if err == nil {
		return nil
	}
	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		// Handle non-ValidationErrors (like InvalidValidationError)
		return fmt.Errorf("validation error: %s", err.Error())
	}
	var errs []string
	for _, e := range validationErrors {
		errs = append(errs, e.Translate(v.transEN))
	}
	return fmt.Errorf("%s", strings.Join(errs, ", "))
}

// registerCustomValidators registers custom validation rules
func registerCustomValidators(validate *validator.Validate, trans ut.Translator) {
	// Register ircusername validator
	if err := validate.RegisterValidation("ircusername", validateIRCUsername); err != nil {
		log.Fatal(err)
	}
	if err := validate.RegisterTranslation("ircusername", trans, func(ut ut.Translator) error {
		return ut.Add("ircusername", "{0} must be a valid IRC username (2-12 chars, alphanumeric only)", true)
	}, func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T("ircusername", fe.Field())
		return t
	}); err != nil {
		log.Fatal(err)
	}

	// Register nocontrolchars validator
	if err := validate.RegisterValidation("nocontrolchars", validateNoControlChars); err != nil {
		log.Fatal(err)
	}
	if err := validate.RegisterTranslation("nocontrolchars", trans, func(ut ut.Translator) error {
		return ut.Add("nocontrolchars", "{0} cannot contain control characters", true)
	}, func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T("nocontrolchars", fe.Field())
		return t
	}); err != nil {
		log.Fatal(err)
	}

	// Register notrimmed validator
	if err := validate.RegisterValidation("notrimmed", validateNotTrimmed); err != nil {
		log.Fatal(err)
	}
	if err := validate.RegisterTranslation("notrimmed", trans, func(ut ut.Translator) error {
		return ut.Add("notrimmed", "{0} cannot have leading or trailing whitespace", true)
	}, func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T("notrimmed", fe.Field())
		return t
	}); err != nil {
		log.Fatal(err)
	}

	// Register alphanumtoken validator
	if err := validate.RegisterValidation("alphanumtoken", validateAlphanumToken); err != nil {
		log.Fatal(err)
	}
	if err := validate.RegisterTranslation("alphanumtoken", trans, func(ut ut.Translator) error {
		return ut.Add("alphanumtoken", "{0} must be alphanumeric", true)
	}, func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T("alphanumtoken", fe.Field())
		return t
	}); err != nil {
		log.Fatal(err)
	}

	// Register meaningful content validator
	if err := validate.RegisterValidation("meaningful", validateMeaningfulContent); err != nil {
		log.Fatal(err)
	}
	if err := validate.RegisterTranslation("meaningful", trans, func(ut ut.Translator) error {
		return ut.Add(
			"meaningful",
			"{0} must contain meaningful content (at least 2 words, no repeated characters)",
			true,
		)
	}, func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T("meaningful", fe.Field())
		return t
	}); err != nil {
		log.Fatal(err)
	}

	// Register CIDR validator
	if err := validate.RegisterValidation("cidr", validateCIDR); err != nil {
		log.Fatal(err)
	}
	if err := validate.RegisterTranslation("cidr", trans, func(ut ut.Translator) error {
		return ut.Add("cidr", "{0} must be a valid CIDR notation (e.g., 192.168.1.0/24 or 2001:db8::/32)", true)
	}, func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T("cidr", fe.Field())
		return t
	}); err != nil {
		log.Fatal(err)
	}

	// Register validscopes validator
	if err := validate.RegisterValidation("validscopes", validateValidScopes); err != nil {
		log.Fatal(err)
	}
	if err := validate.RegisterTranslation("validscopes", trans, func(ut ut.Translator) error {
		return ut.Add("validscopes", "{0} must contain only valid API scopes", true)
	}, func(ut ut.Translator, fe validator.FieldError) string {
		t, _ := ut.T("validscopes", fe.Field())
		return t
	}); err != nil {
		log.Fatal(err)
	}
}

// validateIRCUsername validates IRC username format
func validateIRCUsername(fl validator.FieldLevel) bool {
	username := fl.Field().String()

	// Let required validator handle empty strings
	if username == "" {
		return true
	}

	// Basic length check (already covered by min/max, but double-check)
	if len(username) < 2 || len(username) > 12 {
		return false
	}

	// Must be alphanumeric only
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	return usernameRegex.MatchString(username)
}

// validateNoControlChars ensures string contains no control characters
func validateNoControlChars(fl validator.FieldLevel) bool {
	str := fl.Field().String()

	for _, r := range str {
		// Allow common whitespace characters but reject other control chars
		if unicode.IsControl(r) && r != '\n' && r != '\t' && r != '\r' {
			return false
		}
	}

	return true
}

// validateNotTrimmed ensures string has no leading/trailing whitespace
func validateNotTrimmed(fl validator.FieldLevel) bool {
	str := fl.Field().String()
	return str == strings.TrimSpace(str)
}

// validateAlphanumToken validates that string is alphanumeric (for tokens)
func validateAlphanumToken(fl validator.FieldLevel) bool {
	str := fl.Field().String()
	if str == "" {
		return true // Let required validation handle empty strings
	}

	alphanumRegex := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	return alphanumRegex.MatchString(str)
}

// validateMeaningfulContent ensures text has meaningful content
func validateMeaningfulContent(fl validator.FieldLevel) bool {
	str := fl.Field().String()
	if str == "" {
		return true // Let required validation handle empty strings
	}

	// Check for minimum word count
	words := strings.Fields(str)
	if len(words) < 2 {
		return false
	}

	// Check for repeated characters (more than 50% of the same character)
	if isRepeatedCharacters(str) {
		return false
	}

	// Check for placeholder text
	lowerStr := strings.ToLower(str)
	placeholders := []string{"test", "testing", "placeholder", "insert reason here", "reason here", "lorem ipsum"}
	for _, placeholder := range placeholders {
		if strings.Contains(lowerStr, placeholder) {
			return false
		}
	}

	return true
}

// isRepeatedCharacters checks if the string is mostly repeated characters
func isRepeatedCharacters(s string) bool {
	if len(s) < 3 {
		return false
	}

	// Count character frequency
	charCount := make(map[rune]int)
	nonSpaceCount := 0

	for _, r := range s {
		if r != ' ' && r != '\t' && r != '\n' {
			charCount[r]++
			nonSpaceCount++
		}
	}

	if nonSpaceCount == 0 {
		return false
	}

	// If any single character makes up more than 50% of non-space characters
	for _, count := range charCount {
		if float64(count)/float64(nonSpaceCount) > 0.5 {
			return true
		}
	}

	return false
}

// validateCIDR validates CIDR notation (IPv4 or IPv6)
func validateCIDR(fl validator.FieldLevel) bool {
	cidr := fl.Field().String()

	// Empty strings are valid (let omitempty or required handle them)
	if cidr == "" {
		return true
	}

	// Parse CIDR
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// validateValidScopes validates that a slice contains only valid API scopes
func validateValidScopes(fl validator.FieldLevel) bool {
	// Get the field value
	field := fl.Field()

	// Check if it's a slice
	if field.Kind() != reflect.Slice {
		return false
	}

	// Convert to string slice
	scopes := make([]string, field.Len())
	for i := 0; i < field.Len(); i++ {
		scopes[i] = field.Index(i).String()
	}

	// Use the existing ValidateScopes function
	err := ValidateScopes(scopes)
	return err == nil
}
