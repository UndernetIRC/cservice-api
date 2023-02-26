// Code generated by mockery v2.16.0. DO NOT EDIT.

package mocks

import (
	context "context"

	mock "github.com/stretchr/testify/mock"
	models "github.com/undernetirc/cservice-api/models"

	pgtype "github.com/jackc/pgtype"
)

// Querier is an autogenerated mock type for the Querier type
type Querier struct {
	mock.Mock
}

// CreatePendingUser provides a mock function with given fields: ctx, arg
func (_m *Querier) CreatePendingUser(ctx context.Context, arg models.CreatePendingUserParams) (*string, error) {
	ret := _m.Called(ctx, arg)

	var r0 *string
	if rf, ok := ret.Get(0).(func(context.Context, models.CreatePendingUserParams) *string); ok {
		r0 = rf(ctx, arg)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*string)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, models.CreatePendingUserParams) error); ok {
		r1 = rf(ctx, arg)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateUser provides a mock function with given fields: ctx, arg
func (_m *Querier) CreateUser(ctx context.Context, arg models.CreateUserParams) (models.User, error) {
	ret := _m.Called(ctx, arg)

	var r0 models.User
	if rf, ok := ret.Get(0).(func(context.Context, models.CreateUserParams) models.User); ok {
		r0 = rf(ctx, arg)
	} else {
		r0 = ret.Get(0).(models.User)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, models.CreateUserParams) error); ok {
		r1 = rf(ctx, arg)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeletePendingUserByCookie provides a mock function with given fields: ctx, cookie
func (_m *Querier) DeletePendingUserByCookie(ctx context.Context, cookie *string) error {
	ret := _m.Called(ctx, cookie)

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, *string) error); ok {
		r0 = rf(ctx, cookie)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetGlineByIP provides a mock function with given fields: ctx, host
func (_m *Querier) GetGlineByIP(ctx context.Context, host string) (models.Gline, error) {
	ret := _m.Called(ctx, host)

	var r0 models.Gline
	if rf, ok := ret.Get(0).(func(context.Context, string) models.Gline); ok {
		r0 = rf(ctx, host)
	} else {
		r0 = ret.Get(0).(models.Gline)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, host)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserByEmail provides a mock function with given fields: ctx, email
func (_m *Querier) GetUserByEmail(ctx context.Context, email string) (models.User, error) {
	ret := _m.Called(ctx, email)

	var r0 models.User
	if rf, ok := ret.Get(0).(func(context.Context, string) models.User); ok {
		r0 = rf(ctx, email)
	} else {
		r0 = ret.Get(0).(models.User)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, email)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserByID provides a mock function with given fields: ctx, id
func (_m *Querier) GetUserByID(ctx context.Context, id int32) (models.GetUserByIDRow, error) {
	ret := _m.Called(ctx, id)

	var r0 models.GetUserByIDRow
	if rf, ok := ret.Get(0).(func(context.Context, int32) models.GetUserByIDRow); ok {
		r0 = rf(ctx, id)
	} else {
		r0 = ret.Get(0).(models.GetUserByIDRow)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int32) error); ok {
		r1 = rf(ctx, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserByUsername provides a mock function with given fields: ctx, username
func (_m *Querier) GetUserByUsername(ctx context.Context, username string) (models.User, error) {
	ret := _m.Called(ctx, username)

	var r0 models.User
	if rf, ok := ret.Get(0).(func(context.Context, string) models.User); ok {
		r0 = rf(ctx, username)
	} else {
		r0 = ret.Get(0).(models.User)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, username)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetUserChannels provides a mock function with given fields: ctx, userID
func (_m *Querier) GetUserChannels(ctx context.Context, userID int32) ([]models.GetUserChannelsRow, error) {
	ret := _m.Called(ctx, userID)

	var r0 []models.GetUserChannelsRow
	if rf, ok := ret.Get(0).(func(context.Context, int32) []models.GetUserChannelsRow); ok {
		r0 = rf(ctx, userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.GetUserChannelsRow)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, int32) error); ok {
		r1 = rf(ctx, userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetWhiteListByIP provides a mock function with given fields: ctx, ip
func (_m *Querier) GetWhiteListByIP(ctx context.Context, ip pgtype.Inet) (models.Whitelist, error) {
	ret := _m.Called(ctx, ip)

	var r0 models.Whitelist
	if rf, ok := ret.Get(0).(func(context.Context, pgtype.Inet) models.Whitelist); ok {
		r0 = rf(ctx, ip)
	} else {
		r0 = ret.Get(0).(models.Whitelist)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, pgtype.Inet) error); ok {
		r1 = rf(ctx, ip)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListPendingUsers provides a mock function with given fields: ctx
func (_m *Querier) ListPendingUsers(ctx context.Context) ([]models.Pendinguser, error) {
	ret := _m.Called(ctx)

	var r0 []models.Pendinguser
	if rf, ok := ret.Get(0).(func(context.Context) []models.Pendinguser); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]models.Pendinguser)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewQuerier interface {
	mock.TestingT
	Cleanup(func())
}

// NewQuerier creates a new instance of Querier. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewQuerier(t mockConstructorTestingTNewQuerier) *Querier {
	mock := &Querier{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
