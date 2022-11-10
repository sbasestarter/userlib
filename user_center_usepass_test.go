package userlib

import (
	"context"
	"testing"
	"time"

	"github.com/sbasestarter/bizinters/userinters"
	"github.com/sbasestarter/bizmongolib/mongolib"
	userpassmongo "github.com/sbasestarter/bizmongolib/user/authenticator/userpass"
	"github.com/sbasestarter/userlib/authenticator/userpass"
	"github.com/sbasestarter/userlib/authingdatastorage/memory"
	userpassmanager "github.com/sbasestarter/userlib/manager/userpass"
	"github.com/sbasestarter/userlib/policy/single"
	scmemory "github.com/sbasestarter/userlib/statuscontroller/memory"
	"github.com/stretchr/testify/assert"
)

// nolint
func TestUserPassUserCenter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	uc := NewUserCenter("x", single.NewPolicy(userinters.AuthMethodNameUserPassword),
		scmemory.NewStatusController(), memory.NewMemoryAuthingDataStorage(), nil)

	mongoCli, err := mongolib.InitMongo("mongodb://mongo_default_user:mongo_default_pass@127.0.0.1:8309/my_db")
	assert.Nil(t, err)

	manager := userpassmanager.NewManager("x", userpassmongo.NewMongoUserPasswordModel(mongoCli, "my_db", "users", nil))

	_, err = manager.GetUserByUserName(ctx, "user1")
	if err != nil {
		_, err = manager.Register(ctx, "user1", "pass1")
		assert.Nil(t, err)
	}

	auth, err := userpass.NewAuthenticator("user1", "pass1", manager)
	assert.Nil(t, err)

	resp, err := uc.Login(ctx, &userinters.LoginRequest{
		ContinueID: 0,
		Authenticators: []userinters.Authenticator{
			auth,
		},
		TokenLiveDuration: time.Second,
	})
	assert.Nil(t, err)
	assert.EqualValues(t, userinters.LoginStatusSuccess, resp.Status)

	_, uid, _, err := uc.CheckToken(ctx, resp.Token, false)
	assert.Nil(t, err)
	assert.EqualValues(t, resp.UserID, uid)

	time.Sleep(time.Second * 2)

	_, _, _, err = uc.CheckToken(ctx, resp.Token, false)
	assert.NotNil(t, err)
}
