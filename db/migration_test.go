// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package db

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// mockMigrator is a hand-rolled test double for the Migrator interface.
// Fields capture the last invocation for assertion; *Err fields let a test
// force a specific failure path.
type mockMigrator struct {
	stepsCalledWith int
	stepsErr        error
	upCalled        bool
	upErr           error
	forceCalledWith int
	forceErr        error
	versionResult   uint
	versionErr      error
}

func (m *mockMigrator) Steps(n int) error {
	m.stepsCalledWith = n
	return m.stepsErr
}

func (m *mockMigrator) Version() (uint, bool, error) {
	return m.versionResult, false, m.versionErr
}

func (m *mockMigrator) Up() error {
	m.upCalled = true
	return m.upErr
}

func (m *mockMigrator) Force(v int) error {
	m.forceCalledWith = v
	return m.forceErr
}

// TestMigrationHandler_Step covers MigrationStep against a mock Migrator so
// the success + failure paths (Steps error, Version error) can be verified
// without a live database.
func TestMigrationHandler_Step(t *testing.T) {
	tests := []struct {
		name            string
		step            int
		stepsErr        error
		versionResult   uint
		versionErr      error
		wantErr         bool
		wantVersion     uint
		wantErrContains string
	}{
		{
			name:          "up one succeeds",
			step:          1,
			versionResult: 3,
			wantVersion:   3,
		},
		{
			name:          "down one succeeds",
			step:          -1,
			versionResult: 2,
			wantVersion:   2,
		},
		{
			name:            "steps failure wraps direction",
			step:            1,
			stepsErr:        errors.New("boom"),
			wantErr:         true,
			wantErrContains: "up",
		},
		{
			name:            "steps failure wraps direction (down)",
			step:            -1,
			stepsErr:        errors.New("boom"),
			wantErr:         true,
			wantErrContains: "down",
		},
		{
			name:       "version query failure surfaces",
			step:       1,
			versionErr: errors.New("no version"),
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mockMigrator{
				stepsErr:      tt.stepsErr,
				versionResult: tt.versionResult,
				versionErr:    tt.versionErr,
			}
			h := NewMigrationHandlerWith(m)

			ver, err := h.MigrationStep(tt.step)

			assert.Equal(t, tt.step, m.stepsCalledWith)
			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrContains != "" {
					assert.Contains(t, err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantVersion, ver)
		})
	}
}

// TestMigrationHandler_RunMigrations covers RunMigrations, including
// golang-migrate's "no change" convention which must be treated as success.
func TestMigrationHandler_RunMigrations(t *testing.T) {
	tests := []struct {
		name    string
		upErr   error
		wantErr bool
	}{
		{
			name: "clean apply succeeds",
		},
		{
			name:  "no-change is not an error",
			upErr: errors.New("no change"),
		},
		{
			name:    "other error propagates",
			upErr:   errors.New("boom"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mockMigrator{upErr: tt.upErr}
			h := NewMigrationHandlerWith(m)

			err := h.RunMigrations()

			assert.True(t, m.upCalled)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestMigrationHandler_ForceVersion covers ForceVersion in both the happy
// and failing paths against a mock Migrator.
func TestMigrationHandler_ForceVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  int
		forceErr error
		wantErr  bool
	}{
		{
			name:    "forces requested version",
			version: 42,
		},
		{
			name:     "surfaces forcing error",
			version:  7,
			forceErr: errors.New("boom"),
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mockMigrator{forceErr: tt.forceErr}
			h := NewMigrationHandlerWith(m)

			err := h.ForceVersion(tt.version)

			assert.Equal(t, tt.version, m.forceCalledWith)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
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
