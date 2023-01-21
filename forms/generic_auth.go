package forms

//AdminToken ...
type AdminToken struct {
	RefreshToken string `form:"refresh_token" json:"refresh_token" binding:"required"`
}

//EmpProToken ...
type EmpProToken struct {
	RefreshToken string `form:"refresh_token" json:"refresh_token" binding:"required"`
}

