// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package helper

import (
	"fmt"
	"log"
	"strings"

	"github.com/go-playground/locales/en_US"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	enTranslation "github.com/go-playground/validator/v10/translations/en"
)

type Validator struct {
	validator *validator.Validate
	transEN   ut.Translator
}

func NewValidator() *Validator {
	english := en_US.New()
	uni := ut.New(english, english)
	transEN, found := uni.GetTranslator("en_US")
	if !found {
		log.Fatal("translator not found")
	}
	validate := validator.New()
	if err := enTranslation.RegisterDefaultTranslations(validate, transEN); err != nil {
		log.Fatal(err)
	}
	return &Validator{
		validator: validate,
		transEN:   transEN,
	}
}

func (v *Validator) Validate(i interface{}) error {
	err := v.validator.Struct(i)
	if err == nil {
		return nil
	}
	validationErrors := err.(validator.ValidationErrors)
	var errs []string
	for _, e := range validationErrors {
		errs = append(errs, e.Translate(v.transEN))
	}
	return fmt.Errorf(strings.Join(errs, ", "))
}
