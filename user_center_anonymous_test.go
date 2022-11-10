package userlib

import (
	"context"
	"testing"
	"time"

	"github.com/sbasestarter/bizinters/userinters"
	"github.com/sbasestarter/userlib/authenticator/anonymous"
	"github.com/sbasestarter/userlib/authingdatastorage/memory"
	"github.com/sbasestarter/userlib/policy/single"
	scmemory "github.com/sbasestarter/userlib/statuscontroller/memory"
	"github.com/stretchr/testify/assert"
)

func TestAnonymousUserCenter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uc := NewUserCenter("x", single.NewPolicy(userinters.AuthMethodNameAnonymous),
		scmemory.NewStatusController(), memory.NewMemoryAuthingDataStorage(), nil)

	resp, err := uc.Login(ctx, &userinters.LoginRequest{
		ContinueID: 0,
		Authenticators: []userinters.Authenticator{
			anonymous.NewAuthenticator("userName1"),
		},
		TokenLiveDuration: time.Second,
	})
	assert.Nil(t, err)
	assert.EqualValues(t, userinters.LoginStatusSuccess, resp.Status)

	_, uid, _, err := uc.CheckToken(ctx, resp.Token, false)
	assert.Nil(t, err)
	assert.EqualValues(t, resp.UserID, uid)

	time.Sleep(time.Second * 2)

	_, _, tokenDataList, err := uc.CheckToken(ctx, resp.Token, false)
	assert.NotNil(t, err)

	assert.EqualValues(t, "userName1", tokenDataList[userinters.AuthMethodNameAnonymous])
}

func TestAnonymousUserCenter2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uc := NewUserCenter("x", single.NewPolicy(userinters.AuthMethodNameAnonymous),
		scmemory.NewStatusController(), memory.NewMemoryAuthingDataStorage(), nil)

	resp, err := uc.Login(ctx, &userinters.LoginRequest{
		ContinueID:        0,
		Authenticators:    []userinters.Authenticator{},
		TokenLiveDuration: time.Second,
	})
	assert.Nil(t, err)
	assert.EqualValues(t, userinters.LoginStatusNeedMoreAuthenticator, resp.Status)
	assert.EqualValues(t, []string{userinters.AuthMethodNameAnonymous}, resp.RequiredOrMethods)
}

func TestAnonymousUserCenter3(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uc := NewUserCenter("x", single.NewPolicy(userinters.AuthMethodNameAnonymous),
		scmemory.NewStatusController(), memory.NewMemoryAuthingDataStorage(), nil)

	resp, err := uc.Login(ctx, &userinters.LoginRequest{
		ContinueID: 0,
		Authenticators: []userinters.Authenticator{
			anonymous.NewAuthenticator("userName1"),
		},
		TokenLiveDuration: time.Minute,
	})
	assert.Nil(t, err)
	assert.EqualValues(t, userinters.LoginStatusSuccess, resp.Status)

	_, uid, _, err := uc.CheckToken(ctx, resp.Token, false)
	assert.Nil(t, err)
	assert.EqualValues(t, resp.UserID, uid)
}
