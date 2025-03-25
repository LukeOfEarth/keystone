package db

import (
	bolt "go.etcd.io/bbolt"
)

const dbPath = "keystone.db"
const bucketName = "keystone"

var database *bolt.DB

func InitDB() {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		panic(err.Error())
	}

	database = db

	err2 := database.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	})

	if err2 != nil {
		panic(err2.Error())
	}
}

func CloseDB() {
	if database != nil {
		database.Close()
	}
}

func Query(key string) []byte {
	var res []byte

	if database == nil {
		panic("db not initialized")
	}

	database.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			panic("no bucket found")
		}
		res = b.Get([]byte(key))
		return nil
	})

	return res
}

func Put(key, value string) error {
	var out error

	database.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		err := b.Put([]byte(key), []byte(value))
		out = err
		return err
	})

	return out
}
