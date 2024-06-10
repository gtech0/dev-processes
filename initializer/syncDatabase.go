package initializer

import (
	"dev-processes/model"
	"log"
)

func SyncDatabase() {
	err := DB.AutoMigrate(&model.User{}, &model.Token{})
	if err != nil {
		log.Fatal(err)
	}
}
