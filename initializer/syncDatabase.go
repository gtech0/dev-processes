package initializer

import (
	"dev-processes/model"
	"log"
)

func SyncDatabase() {
	err := DB.AutoMigrate(&model.User{}, &model.Token{}, &model.Stream{})
	if err != nil {
		log.Fatal(err)
	}
}
