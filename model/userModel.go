package model

import (
	"github.com/guregu/null/v5"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name        string
	Surname     string
	Login       string `gorm:"unique;not null;default:null"`
	Password    string
	Deactivated bool
	StreamName  null.String
	Comment     null.String
	Role        Role `gorm:"type:role;not null;default:null"`
	Tokens      []Token
}
