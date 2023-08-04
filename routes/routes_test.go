// SPDX-License-Identifier: MIT
// SPDX-FileCopyRightText: Copyright (c) 2023 UnderNET

package routes

import (
	"fmt"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/undernetirc/cservice-api/db/mocks"
)

func TestRoutes(t *testing.T) {
	db := mocks.NewQuerier(t)
	e := echo.New()
	r := NewRouteService(e, db, nil, nil)
	r.routerGroup = e.Group("/test")

	r.UserRoutes()
	r.MeRoutes()
	r.AuthnRoutes()

	testCases := []struct {
		path   string
		method string
	}{
		{"/test/users/:id", "GET"},
		{"/test/me", "GET"},
		{"/v1/authn/logout", "POST"},
		{"/v1/authn/refresh", "POST"},
		{"/v1/authn/factor_verify", "POST"},
		{"/v1/authn/register", "POST"},
	}

	routeMap := make(map[string]string)
	for _, v := range e.Routes() {
		routeMap[fmt.Sprintf("%s:%s", v.Path, v.Method)] = "1"
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			if _, ok := routeMap[fmt.Sprintf("%s:%s", tc.path, tc.method)]; !ok {
				t.Errorf("expected to find path %s with method %s, but did not", tc.path, tc.method)
			}
		})
	}
}
