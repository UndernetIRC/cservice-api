// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestViewMigration tests the ViewMigration function
func TestViewMigration(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantErr  bool
		wantData []byte
	}{
		{
			name:     "existing migration file",
			file:     "migrations/20221228143054_cservice_web_schema.up.sql",
			wantErr:  false,
			wantData: []byte("CREATE TABLE pendingusers"),
		},
		{
			name:     "non-existent file",
			file:     "migrations/nonexistent.sql",
			wantErr:  true,
			wantData: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := ViewMigration(tt.file)
			if tt.wantErr {
				assert.Empty(t, data)
			} else {
				assert.NotEmpty(t, data)
				assert.Contains(t, string(data), string(tt.wantData))
			}
		})
	}
}

// TestMigrationHandler_Step tests the MigrationStep method
func TestMigrationHandler_Step(t *testing.T) {
	// This test is skipped because it requires mocking the migrate.Migrate interface
	// which is difficult to do without modifying the original code
	t.Skip("TestMigrationHandler_Step requires mocking the migrate.Migrate interface")
}

// TestMigrationHandler_RunMigrations tests the RunMigrations method
func TestMigrationHandler_RunMigrations(t *testing.T) {
	// This test is skipped because it requires mocking the migrate.Migrate interface
	// which is difficult to do without modifying the original code
	t.Skip("TestMigrationHandler_RunMigrations requires mocking the migrate.Migrate interface")
}

// TestNewMigrationHandler tests the NewMigrationHandler function
func TestNewMigrationHandler(t *testing.T) {
	// This test is skipped because it requires a real database connection
	// which is difficult to set up in a test environment
	t.Skip("TestNewMigrationHandler requires a real database connection")
}

// TestListMigrations tests the ListMigrations function
func TestListMigrations(t *testing.T) {
	files, err := ListMigrations()
	assert.NoError(t, err)
	assert.NotEmpty(t, files)

	// Check that we have at least one migration file
	found := false
	for _, file := range files {
		if file == "migrations/20221228143054_cservice_web_schema.up.sql" {
			found = true
			break
		}
	}
	assert.True(t, found, "Expected to find the cservice_web_schema.up.sql migration file")
}
