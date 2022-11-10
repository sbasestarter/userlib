package single

import (
	"context"

	"github.com/sbasestarter/bizinters/userinters"
	"github.com/sgostarter/libeasygo/commerr"
)

func NewPolicy(requiredMethodName string) userinters.Policy {
	return &policyImpl{
		requiredMethodName: requiredMethodName,
	}
}

type policyImpl struct {
	requiredMethodName string
}

func (impl *policyImpl) RequireAuthMethod(_ context.Context, d *userinters.AuthForUserPolicy) (requiredOrMethods []string, err error) {
	if d == nil {
		err = commerr.ErrInvalidArgument

		return
	}

	for _, method := range d.VerifiedMethods {
		if method.MethodName == impl.requiredMethodName {
			return
		}
	}

	requiredOrMethods = append(requiredOrMethods, impl.requiredMethodName)

	return
}
