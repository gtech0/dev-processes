package model

import (
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

type Role string

const (
	Admin   Role = "Admin"
	Dean    Role = "Dean"
	Student Role = "Student"
)
