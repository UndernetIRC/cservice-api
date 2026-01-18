// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

// Package channel provides channel-related utilities and settings management.
package channel

import "github.com/undernetirc/cservice-api/db/types/flags"

// SettingType represents the data type of a channel setting.
type SettingType int

const (
	TypeBool SettingType = iota
	TypeInt
	TypeString
)

// SettingDef defines a channel setting with its metadata.
type SettingDef struct {
	Name     string        // JSON field name
	DBColumn string        // Database column name
	Type     SettingType   // Data type
	Level    int32         // Minimum access level required
	Flag     flags.Channel // For boolean flags stored in flags column
	Min      *int          // For integers: minimum value
	Max      *int          // For integers: maximum value
	MaxLen   *int          // For strings: max length
}

func ptr(i int) *int { return &i }

// Settings is the registry of all configurable channel settings.
var Settings = []SettingDef{
	// Level 500 settings (Channel Manager)
	{Name: "autojoin", DBColumn: "flags", Type: TypeBool, Level: 500, Flag: flags.ChannelAutoJoin},
	{Name: "massdeoppro", DBColumn: "mass_deop_pro", Type: TypeInt, Level: 500, Min: ptr(0), Max: ptr(7)},
	{Name: "noop", DBColumn: "flags", Type: TypeBool, Level: 500, Flag: flags.ChannelNoOp},
	{Name: "strictop", DBColumn: "flags", Type: TypeBool, Level: 500, Flag: flags.ChannelStrictOp},

	// Level 450 settings (Trusted Channel Admin)
	{Name: "autotopic", DBColumn: "flags", Type: TypeBool, Level: 450, Flag: flags.ChannelAutoTopic},
	{Name: "description", DBColumn: "description", Type: TypeString, Level: 450, MaxLen: ptr(300)},
	{Name: "floatlim", DBColumn: "flags", Type: TypeBool, Level: 450, Flag: flags.ChannelFloatLimit},
	{Name: "floatgrace", DBColumn: "limit_grace", Type: TypeInt, Level: 450, Min: ptr(0), Max: ptr(19)},
	{Name: "floatmargin", DBColumn: "limit_offset", Type: TypeInt, Level: 450, Min: ptr(2), Max: ptr(20)},
	{Name: "floatmax", DBColumn: "limit_max", Type: TypeInt, Level: 450, Min: ptr(0), Max: ptr(65536)},
	{Name: "floatperiod", DBColumn: "limit_period", Type: TypeInt, Level: 450, Min: ptr(20), Max: ptr(200)},
	{Name: "keywords", DBColumn: "keywords", Type: TypeString, Level: 450, MaxLen: ptr(300)},
	{Name: "url", DBColumn: "url", Type: TypeString, Level: 450, MaxLen: ptr(128)},
	{Name: "userflags", DBColumn: "userflags", Type: TypeInt, Level: 450, Min: ptr(0), Max: ptr(2)},
}

// GetSettingByName returns the setting definition for the given name, or nil if not found.
func GetSettingByName(name string) *SettingDef {
	for i := range Settings {
		if Settings[i].Name == name {
			return &Settings[i]
		}
	}
	return nil
}
