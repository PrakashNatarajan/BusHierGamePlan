package forms

import (
	"encoding/json"

	"github.com/go-playground/validator/v10"
)

//EmpUserForm ...
type EmpUserForm struct{}

//EmpLoginForm ...
type EmpLoginForm struct {
	Email    string `form:"email" json:"email" binding:"required,email"`
	Password string `form:"password" json:"password" binding:"required,min=3,max=50"`
}

//EmpRegisterForm ...
type EmpRegisterForm struct {
	Name     string `form:"name" json:"name" binding:"required,min=3,max=20,fullName"` //fullName rule is in validator.go
	Email    string `form:"email" json:"email" binding:"required,email"`
	Password string `form:"password" json:"password" binding:"required,min=3,max=50"`
}

//Name ...
func (frm EmpUserForm) Name(tag string, errMsg ...string) (message string) {
	switch tag {
	case "required":
		if len(errMsg) == 0 {
			return "Please enter your name"
		}
		return errMsg[0]
	case "min", "max":
		return "Your name should be between 3 to 20 characters"
	case "fullName":
		return "Name should not include any special characters or numbers"
	default:
		return "Something went wrong, please try again later"
	}
}

//Email ...
func (frm EmpUserForm) Email(tag string, errMsg ...string) (message string) {
	switch tag {
	case "required":
		if len(errMsg) == 0 {
			return "Please enter your email"
		}
		return errMsg[0]
	case "min", "max", "email":
		return "Please enter a valid email"
	default:
		return "Something went wrong, please try again later"
	}
}

//Password ...
func (frm EmpUserForm) Password(tag string) (message string) {
	switch tag {
	case "required":
		return "Please enter your password"
	case "min", "max":
		return "Your password should be between 3 and 50 characters"
	case "eqfield":
		return "Your passwords does not match"
	default:
		return "Something went wrong, please try again later"
	}
}

//Signin ...
func (frm EmpUserForm) Login(err error) string {
	switch err.(type) {
	case validator.ValidationErrors:

		if _, ok := err.(*json.UnmarshalTypeError); ok {
			return "Something went wrong, please try again later"
		}

		for _, err := range err.(validator.ValidationErrors) {
			if err.Field() == "Email" {
				return frm.Email(err.Tag())
			}
			if err.Field() == "Password" {
				return frm.Password(err.Tag())
			}
		}

	default:
		return "Invalid request"
	}

	return "Something went wrong, please try again later"
}

//Register ...
func (frm EmpUserForm) Register(err error) string {
	switch err.(type) {
	case validator.ValidationErrors:

		if _, ok := err.(*json.UnmarshalTypeError); ok {
			return "Something went wrong, please try again later"
		}

		for _, err := range err.(validator.ValidationErrors) {
			if err.Field() == "Name" {
				return frm.Name(err.Tag())
			}

			if err.Field() == "Email" {
				return frm.Email(err.Tag())
			}

			if err.Field() == "Password" {
				return frm.Password(err.Tag())
			}

		}
	default:
		return "Invalid request"
	}

	return "Something went wrong, please try again later"
}
