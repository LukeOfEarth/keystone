package tests

import (
	"keystone/lib/db"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDb(t *testing.T) {
	t.Run("Test DB Init", func(t *testing.T) {
		database := db.InitDB(dbPath)
		p := database.Path()
		assert.Equal(t, p, dbPath)
	})
}
