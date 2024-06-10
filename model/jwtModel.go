package model

import "gorm.io/gorm"

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Token struct {
	gorm.Model
	UserID  uint
	Token   string `gorm:"unique;not null"`
	Revoked bool
}
