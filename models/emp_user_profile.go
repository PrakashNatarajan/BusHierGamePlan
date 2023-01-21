package models

import (
	"errors"
    "log"
	"time"
	"strings"
	"BusHierGamePlan/db"
	"BusHierGamePlan/forms"

	"golang.org/x/crypto/bcrypt"
)

//EmpUser ...
type EmpUser struct {
	ID        int64  `db:"id, primarykey, autoincrement" json:"id"`
	Email     string `db:"email" json:"email"`
	Password  string `db:"password" json:"-"`
	Name      string `db:"name" json:"name"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt *time.Time `db:"updated_at" json:"created_at"`
}

//EmpUserModel ...
type EmpUserModel struct{}

var fmrAuthModel = new(FormerAuthModel)

//Login ...
func (m EmpUserModel) Login(form forms.FormerLoginForm) (empUser EmpUser, fmrToken FormerToken, err error) {

	err = db.GetDB().SelectOne(&empUser, "SELECT id, email, password, name, updated_at, created_at FROM former_user_profiles WHERE email=LOWER($1) LIMIT 1", form.Email)

	if err != nil {
		return empUser, fmrToken, err
	}

	//Compare the password form and database if match
	bytePassword := []byte(form.Password)
	byteHashedPassword := []byte(empUser.Password)

	err = bcrypt.CompareHashAndPassword(byteHashedPassword, bytePassword)

	if err != nil {
		return empUser, fmrToken, err
	}

	//Generate the JWT auth fmrToken
	tokenDetails, err := fmrAuthModel.CreateToken(empUser.ID)
	if err != nil {
		return empUser, fmrToken, err
	}

	saveErr := fmrAuthModel.CreateAuth(empUser.ID, tokenDetails)
	if saveErr == nil {
		fmrToken.AccessToken = tokenDetails.AccessToken
		fmrToken.RefreshToken = tokenDetails.RefreshToken
	}

	return empUser, fmrToken, nil
}

//Register ...
func (m EmpUserModel) Register(form forms.FormerRegisterForm) (empUser EmpUser, err error) {
	getDb := db.GetDB()

	//Check if the empUser exists in database
	checkUser, err := getDb.SelectInt("SELECT count(id) FROM former_user_profiles WHERE email=LOWER($1) LIMIT 1", form.Email)
	if err != nil {
		return empUser, errors.New("something went wrong, please try again later")
	}

	if checkUser > 0 {
		return empUser, errors.New("email already exists")
	}

	bytePassword := []byte(form.Password)
	hashedPassword, err := bcrypt.GenerateFromPassword(bytePassword, bcrypt.DefaultCost)
	if err != nil {
		return empUser, errors.New("something went wrong, please try again later")
	}

	//Create the empUser and return back the empUser ID
	err = getDb.QueryRow("INSERT INTO former_user_profiles(email, password, name) VALUES($1, $2, $3) RETURNING id", strings.ToLower(form.Email), string(hashedPassword), form.Name).Scan(&empUser.ID)
	if err != nil {
	    log.Println(err)
		return empUser, errors.New("something went wrong, please try again later")
	}

	empUser.Name = form.Name
	empUser.Email = form.Email

	return empUser, err
}

//One ...
func (m EmpUserModel) One(userID int64) (empUser EmpUser, err error) {
	err = db.GetDB().SelectOne(&empUser, "SELECT id, email, name FROM former_user_profiles WHERE id=$1 LIMIT 1", userID)
	return empUser, err
}
