package userlib

import (
	"context"
	"testing"
	"time"

	"github.com/sbasestarter/bizinters/userinters"
	"github.com/sbasestarter/userlib/authenticator/anonymous"
	"github.com/sbasestarter/userlib/policy/single"
	"github.com/sbasestarter/userlib/statuscontroller/memory"
	"github.com/stretchr/testify/assert"
)

func TestAnonymousUserCenter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uc := NewUserCenter("x", single.NewPolicy(userinters.AuthMethodNameAnonymous),
		memory.NewStatusController(), nil)

	resp, err := uc.Login(ctx, &userinters.LoginRequest{
		ContinueID: 0,
		Authenticators: []userinters.Authenticator{
			anonymous.NewAuthenticator(),
		},
		TokenLiveDuration: time.Second,
	})
	assert.Nil(t, err)
	assert.EqualValues(t, userinters.LoginStatusSuccess, resp.Status)

	uid, err := uc.CheckToken(ctx, resp.Token)
	assert.Nil(t, err)
	assert.EqualValues(t, resp.UserID, uid)

	time.Sleep(time.Second * 2)

	_, err = uc.CheckToken(ctx, resp.Token)
	assert.NotNil(t, err)
}

func TestAnonymousUserCenter2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uc := NewUserCenter("x", single.NewPolicy(userinters.AuthMethodNameAnonymous),
		memory.NewStatusController(), nil)

	resp, err := uc.Login(ctx, &userinters.LoginRequest{
		ContinueID:        0,
		Authenticators:    []userinters.Authenticator{},
		TokenLiveDuration: time.Second,
	})
	assert.Nil(t, err)
	assert.EqualValues(t, userinters.LoginStatusNeedMoreAuthenticator, resp.Status)
	assert.EqualValues(t, []string{userinters.AuthMethodNameAnonymous}, resp.RequiredOrMethods)
}
