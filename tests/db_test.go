package tests

import (
	"keystone/lib/db"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDb(t *testing.T) {
	t.Run("Test DB Init", func(t *testing.T) {
		t.Cleanup(deleteTestDb)

		database := db.InitDB(dbPath)
		p := database.Path()
		assert.Equal(t, p, dbPath)
	})

	t.Run("Test DB Remove", func(t *testing.T) {
		setupTestDb()

		db.ClearDB(dbPath)
		f, err := os.OpenFile(dbPath, 0, 0600)
		assert.Error(t, err)
		assert.Nil(t, f)
	})

	t.Run("Test DB Update", func(t *testing.T) {
		setupTestDb()
		t.Cleanup(deleteTestDb)

		testCases := []struct {
			name     string
			key      string
			value    string
			expected string
		}{
			{"Test insert", "testNewKey", "inserted", "inserted"},
			{"Test update", "testKey", "updated", "updated"},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				err := db.Put(testCase.key, testCase.value)
				assert.NoError(t, err)

				found := db.Get(testCase.key)
				assert.Equal(t, string(found), testCase.expected)
			})
		}
	})

	t.Run("Test DB Get", func(t *testing.T) {
		setupTestDb()
		t.Cleanup(deleteTestDb)

		testCases := []struct {
			name     string
			key      string
			expected []byte
		}{
			{"Test valid key", "testKey", []byte("testValue")},
			{"Test invalid key", "testInvalidKey", nil},
		}

		for _, testCase := range testCases {
			t.Run(testCase.name, func(t *testing.T) {
				found := db.Get(testCase.key)
				assert.Equal(t, found, testCase.expected)
			})
		}
	})

	t.Run("Test DB Delete", func(t *testing.T) {
		setupTestDb()
		t.Cleanup(deleteTestDb)

		testCases := []struct {
			name string
			key  string
		}{
			{"Test valid key", "testKey"},
			{"Test invalid key", "testInvalidKey"},
		}

		for _, testCase := range testCases {
			err := db.Delete(testCase.key)
			assert.Nil(t, err)
			found := db.Get(testCase.key)
			assert.Nil(t, found)
		}
	})
}
