package userlib

import (
	"context"
	"encoding/json"
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
			anonymous.NewAuthenticator(map[string]interface{}{
				"userName": "userName1",
			}),
		},
		TokenLiveDuration: time.Second,
	})
	assert.Nil(t, err)
	assert.EqualValues(t, userinters.LoginStatusSuccess, resp.Status)

	_, uid, tokenDataList, err := uc.CheckToken(ctx, resp.Token, false)
	assert.Nil(t, err)
	assert.EqualValues(t, resp.UserID, uid)

	ds := make(map[string]interface{})
	_ = json.Unmarshal(tokenDataList[userinters.AuthMethodNameAnonymous], &ds)
	assert.EqualValues(t, "userName1", ds["userName"])

	time.Sleep(time.Second * 2)

	// nolint: dogsled
	_, _, _, err = uc.CheckToken(ctx, resp.Token, false)
	assert.NotNil(t, err)
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
			anonymous.NewAuthenticator(map[string]interface{}{
				"userName": "userName1",
			}),
		},
		TokenLiveDuration: time.Minute,
	})
	assert.Nil(t, err)
	assert.EqualValues(t, userinters.LoginStatusSuccess, resp.Status)

	_, uid, _, err := uc.CheckToken(ctx, resp.Token, false)
	assert.Nil(t, err)
	assert.EqualValues(t, resp.UserID, uid)
}
