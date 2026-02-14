// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2025 UnderNET

package channel

// FullSettingsRequest is used for PUT requests where all fields are required.
type FullSettingsRequest struct {
	Autojoin    bool   `json:"autojoin"`
	Massdeoppro int    `json:"massdeoppro"  validate:"min=0,max=7"`
	Noop        bool   `json:"noop"`
	Strictop    bool   `json:"strictop"`
	Autotopic   bool   `json:"autotopic"`
	Description string `json:"description"  validate:"max=300,nocontrolchars"`
	Floatlim    bool   `json:"floatlim"`
	Floatgrace  int    `json:"floatgrace"   validate:"min=0,max=19"`
	Floatmargin int    `json:"floatmargin"  validate:"min=2,max=20"`
	Floatmax    int    `json:"floatmax"     validate:"min=0,max=65536"`
	Floatperiod int    `json:"floatperiod"  validate:"min=20,max=200"`
	Keywords    string `json:"keywords"     validate:"max=300,nocontrolchars"`
	URL         string `json:"url"          validate:"omitempty,url,max=128"`
	Userflags   int    `json:"userflags"    validate:"min=0,max=2"`
}

// PartialSettingsRequest is used for PATCH requests where only provided fields are updated.
type PartialSettingsRequest struct {
	Autojoin    *bool   `json:"autojoin,omitempty"`
	Massdeoppro *int    `json:"massdeoppro,omitempty"  validate:"omitempty,min=0,max=7"`
	Noop        *bool   `json:"noop,omitempty"`
	Strictop    *bool   `json:"strictop,omitempty"`
	Autotopic   *bool   `json:"autotopic,omitempty"`
	Description *string `json:"description,omitempty"  validate:"omitempty,max=300,nocontrolchars"`
	Floatlim    *bool   `json:"floatlim,omitempty"`
	Floatgrace  *int    `json:"floatgrace,omitempty"   validate:"omitempty,min=0,max=19"`
	Floatmargin *int    `json:"floatmargin,omitempty"  validate:"omitempty,min=2,max=20"`
	Floatmax    *int    `json:"floatmax,omitempty"     validate:"omitempty,min=0,max=65536"`
	Floatperiod *int    `json:"floatperiod,omitempty"  validate:"omitempty,min=20,max=200"`
	Keywords    *string `json:"keywords,omitempty"     validate:"omitempty,max=300,nocontrolchars"`
	URL         *string `json:"url,omitempty"          validate:"omitempty,url,max=128"`
	Userflags   *int    `json:"userflags,omitempty"    validate:"omitempty,min=0,max=2"`
}

// ResponseSettings represents the settings portion of a channel response.
type ResponseSettings struct {
	Autojoin    bool   `json:"autojoin"`
	Massdeoppro int    `json:"massdeoppro"`
	Noop        bool   `json:"noop"`
	Strictop    bool   `json:"strictop"`
	Autotopic   bool   `json:"autotopic"`
	Description string `json:"description,omitempty"`
	Floatlim    bool   `json:"floatlim"`
	Floatgrace  int    `json:"floatgrace"`
	Floatmargin int    `json:"floatmargin"`
	Floatmax    int    `json:"floatmax"`
	Floatperiod int    `json:"floatperiod"`
	Keywords    string `json:"keywords,omitempty"`
	URL         string `json:"url,omitempty"`
	Userflags   int    `json:"userflags"`
}

// GetChannelSettingsResponse is the response for GET /channels/{id}.
type GetChannelSettingsResponse struct {
	ID          int32            `json:"id"`
	Name        string           `json:"name"`
	MemberCount int32            `json:"member_count"`
	CreatedAt   int32            `json:"created_at"`
	UpdatedAt   int32            `json:"updated_at,omitempty"`
	Settings    ResponseSettings `json:"settings"`
}

// UpdateChannelSettingsResponse is the response for PUT/PATCH /channels/{id}.
type UpdateChannelSettingsResponse struct {
	ID          int32            `json:"id"`
	Name        string           `json:"name"`
	MemberCount int32            `json:"member_count"`
	CreatedAt   int32            `json:"created_at"`
	UpdatedAt   int32            `json:"updated_at"`
	Settings    ResponseSettings `json:"settings"`
}
