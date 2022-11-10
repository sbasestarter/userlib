package anonymous

import (
	"context"

	"github.com/godruoyi/go-snowflake"
	"github.com/sbasestarter/bizinters/userinters"
)

func NewAuthenticator(userName string) userinters.Authenticator {
	return &authenticator{
		userName: userName,
	}
}

type authenticator struct {
	userName string
}

func (impl *authenticator) GetMethodName() (method string) {
	return userinters.AuthMethodNameAnonymous
}

func (impl *authenticator) Verify(_ context.Context) (uid uint64, tokenData string, ok bool, _ error) {
	uid = snowflake.ID()
	tokenData = impl.userName
	ok = true

	return
}
