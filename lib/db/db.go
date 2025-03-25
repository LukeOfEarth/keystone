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

func List(target int) [][]byte {
	var data [][]byte

	database.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			panic("no bucket found")
		}

		b.ForEach(func(k, v []byte) error {
			if target == 0 {
				data = append(data, k)
			} else {
				data = append(data, v)
			}
			return nil
		})
		return nil
	})

	return data
}

func Get(key string) []byte {
	var data []byte

	database.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			panic("no bucket found")
		}
		data = b.Get([]byte(key))
		return nil
	})

	return data
}

func Put(key, value string) error {
	return database.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		err := b.Put([]byte(key), []byte(value))
		return err
	})
}

func Delete(key string) error {
	return database.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		err := b.Delete([]byte(key))
		return err
	})
}
