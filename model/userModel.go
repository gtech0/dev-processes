package model

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Login    string `gorm:"unique;not null" json:"login"`
	Password string `json:"password"`
	Tokens   []Token
}
