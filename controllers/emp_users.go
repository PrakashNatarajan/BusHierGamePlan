package controllers

import (
	"BusHierGamePlan/forms"
	"BusHierGamePlan/models"

	"net/http"

	"github.com/gin-gonic/gin"
)

//EmpUsersController ...
type EmpUsersController struct{}

var empUsrModel = new(models.EmpUserModel)
var empUsrForm = new(forms.EmpUserForm)

//getUserID ...
func getUserID(c *gin.Context) (userID int64) {
	//MustGet returns the value for the given key if it exists, otherwise it panics.
	return c.MustGet("userID").(int64)
}

//Login ...
func (ctrl EmpUsersController) Login(c *gin.Context) {
	var fmrLoginForm forms.FormerLoginForm

	if validationErr := c.ShouldBindJSON(&fmrLoginForm); validationErr != nil {
		message := empUsrForm.Login(validationErr)
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": message})
		return
	}

	user, token, err := empUsrModel.Login(fmrLoginForm)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": "Invalid login details"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged in", "user": user, "token": token})
}

//Register ...
func (ctrl EmpUsersController) Register(c *gin.Context) {
	var fmrRegisterForm forms.FormerRegisterForm

	if validationErr := c.ShouldBindJSON(&fmrRegisterForm); validationErr != nil {
		message := empUsrForm.Register(validationErr)
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": message})
		return
	}

	user, err := empUsrModel.Register(fmrRegisterForm)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully registered", "user": user})
}

//Logout ...
func (ctrl EmpUsersController) Logout(c *gin.Context) {

	au, err := fmrAuthModel.ExtractTokenMetadata(c.Request)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": "User not logged in"})
		return
	}

	deleted, delErr := fmrAuthModel.DeleteAuth(au.AccessUUID)
	if delErr != nil || deleted == 0 { //if any goes wrong
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid request"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}
