package initializer

import (
	"dev-processes/model"
	"log"
)

func SyncDatabase() {
	DB.Debug().Exec(`
    DO $$ BEGIN
        CREATE TYPE role AS ENUM ('Admin','Dean','Student');
    EXCEPTION
        WHEN duplicate_object THEN null;
    END $$;`)

	err := DB.AutoMigrate(&model.User{}, &model.Token{}, &model.Stream{})
	if err != nil {
		log.Fatal(err)
	}
}
