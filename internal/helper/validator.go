// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

// Package helper provides helper functions
package helper

import (
	"fmt"
	"log"
	"reflect"
	"strings"

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
	if err := enTranslation.RegisterDefaultTranslations(validate, transEN); err != nil {
		log.Fatal(err)
	}
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
