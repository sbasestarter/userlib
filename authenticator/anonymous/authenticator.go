package anonymous

import (
	"context"

	"github.com/godruoyi/go-snowflake"
	"github.com/sbasestarter/bizinters/userinters"
)

func NewAuthenticator() userinters.Authenticator {
	return &authenticator{}
}

type authenticator struct {
}

func (impl *authenticator) GetMethodName() (method string) {
	return userinters.AuthMethodNameAnonymous
}

func (impl *authenticator) Verify(_ context.Context) (uid uint64, ok bool, _ error) {
	uid = snowflake.ID()
	ok = true

	return
}
