package model

import "gorm.io/gorm"

type Stream struct {
	gorm.Model
	Name string `gorm:"unique;not null;default:null"`
	Code string `gorm:"unique;size:10"`
}
