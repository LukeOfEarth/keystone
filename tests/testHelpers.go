package tests

import (
	"keystone/lib/db"
	"log"

	bolt "go.etcd.io/bbolt"
)

const dbPath string = "keystone-test.db"

func setupTestDb() {
	database := db.InitDB(dbPath)
	database.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("keystone"))
		if b == nil {
			log.Fatalln("No database bucket found")
		}
		err := b.Put([]byte("testKey"), []byte("testValue"))
		return err
	})
}

func deleteTestDb() {
	db.ClearDB(dbPath)
}
