package anonymous

import (
	"context"
	"encoding/json"

	"github.com/godruoyi/go-snowflake"
	"github.com/sbasestarter/bizinters/userinters"
)

func NewAuthenticator(ds map[string]interface{}) userinters.Authenticator {
	return &authenticator{
		ds: ds,
	}
}

type authenticator struct {
	ds map[string]interface{}
}

func (impl *authenticator) GetMethodName() (method string) {
	return userinters.AuthMethodNameAnonymous
}

func (impl *authenticator) Verify(_ context.Context) (uid uint64, tokenData []byte, ok bool, err error) {
	uid = snowflake.ID()

	if len(impl.ds) > 0 {
		tokenData, err = json.Marshal(impl.ds)
		if err != nil {
			return
		}
	}

	ok = true

	return
}
