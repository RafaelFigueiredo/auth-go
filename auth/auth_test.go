package auth

import "testing"

func TestConnectionString(t *testing.T) {
	tt := struct {
		dbConfig         DatabaseConfig
		connectionString string
	}{
		DatabaseConfig{
			Host:     "127.0.0.1:3306",
			Database: "jujuba",
			Username: "root",
			Password: "a1b2c3d4e5",
		},
		"root:a1b2c3d4e5@tcp(127.0.0.1:3306)/jujuba",
	}

	c := tt.dbConfig.getConnectionString()

	if c != tt.connectionString {
		t.Errorf("Connection string error, expected:, got:%s", c)
	}
}
