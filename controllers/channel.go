// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Copyright (c) 2023 UnderNET

package controllers

import (
	"github.com/undernetirc/cservice-api/models"
)

type ChannelController struct {
	s models.Querier
}

func NewChannelController(s models.Querier) *ChannelController {
	return &ChannelController{s: s}
}

func (ctr *ChannelController) GetChannel() {

}
