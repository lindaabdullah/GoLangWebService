// Package validation contains custom validation functions for the application to use for input validation.
package validation

import (
	"github.com/go-playground/validator/v10"
)

func StatusValidator(fl validator.FieldLevel) bool {
	value := fl.Field().String()

	if value == "created" || value == "completed" {
		return true
	}
	return false
}

// FieldValidator is a validation function that checks if the field value is empty.
// It returns true if the field value is not empty, and false otherwise.
func FieldValidator(fl validator.FieldLevel) bool {
	value := fl.Field().String()
	if value == "" {
		return false
	}
    return true
}