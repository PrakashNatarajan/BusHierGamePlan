package forms

//AdminToken ...
type AdminToken struct {
	RefreshToken string `form:"refresh_token" json:"refresh_token" binding:"required"`
}

//EmpToken ...
type EmpToken struct {
	RefreshToken string `form:"refresh_token" json:"refresh_token" binding:"required"`
}

