package model

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Name        string
	Surname     string
	Login       string `gorm:"unique;not null"`
	Password    string
	Deactivated bool
	StreamName  string
	Comment     string
	Role        string `gorm:"not null"`
	Tokens      []Token
}
