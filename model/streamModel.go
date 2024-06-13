package model

import "gorm.io/gorm"

type Stream struct {
	gorm.Model
	Name string `gorm:"unique;not null"`
	Code string `gorm:"size:10"`
}
