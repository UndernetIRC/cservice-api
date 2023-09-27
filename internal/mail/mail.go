// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package mail

import (
	"github.com/wneessen/go-mail"
)

type ContentType int

type EmailData struct {
	From        string
	To          string
	Subject     string
	Message     string
	HTMLMessage string
	Headers     []*header
	ContentType ContentType
}

type header struct {
	Header mail.Header
}
