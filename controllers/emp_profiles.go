package controllers

import (
	"BusHierGamePlan/forms"
	"BusHierGamePlan/models"

	"net/http"

	"github.com/gin-gonic/gin"
)

//EmpProsController ...
type EmpProsController struct{}

var empProModel = new(models.EmpProfileModel)
var empProForm = new(forms.EmpProfileForm)

//getUserID ...
func getUserID(c *gin.Context) (userID int64) {
	//MustGet returns the value for the given key if it exists, otherwise it panics.
	return c.MustGet("userID").(int64)
}

//Login ...
func (ctrl EmpProsController) Login(c *gin.Context) {
	var empLoginForm forms.EmpProLoginForm

	if validationErr := c.ShouldBindJSON(&empLoginForm); validationErr != nil {
		message := empProForm.Login(validationErr)
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": message})
		return
	}

	user, token, err := empProModel.Login(empLoginForm)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": "Invalid login details"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged in", "user": user, "token": token})
}

//Register ...
func (ctrl EmpProsController) Register(c *gin.Context) {
	var empRegisterForm forms.EmpProRegisterForm

	if validationErr := c.ShouldBindJSON(&empRegisterForm); validationErr != nil {
		message := empProForm.Register(validationErr)
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": message})
		return
	}

	user, err := empProModel.Register(empRegisterForm)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusNotAcceptable, gin.H{"message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully registered", "user": user})
}

//Logout ...
func (ctrl EmpProsController) Logout(c *gin.Context) {

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
