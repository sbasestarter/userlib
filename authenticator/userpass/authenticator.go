package userpass

import (
	"context"

	"github.com/sbasestarter/bizinters/userinters"
	inters "github.com/sbasestarter/bizinters/userinters/userpass"
	"github.com/sgostarter/libeasygo/commerr"
)

func NewAuthenticator(user, password string, verifier inters.UserPasswordVerifier) (userinters.Authenticator, error) {
	if verifier == nil {
		return nil, commerr.ErrInvalidArgument
	}

	return &authenticator{
		user:     user,
		password: password,
		verifier: verifier,
	}, nil
}

type authenticator struct {
	user     string
	password string
	verifier inters.UserPasswordVerifier
}

func (impl *authenticator) GetMethodName() string {
	return userinters.AuthMethodNameUserPassword
}

func (impl *authenticator) Verify(ctx context.Context) (uid uint64, ok bool, err error) {
	return impl.verifier.Verify(ctx, impl.user, impl.password)
}
