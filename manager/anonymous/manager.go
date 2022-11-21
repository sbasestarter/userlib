package anonymous

import (
	"context"
	"encoding/json"

	"github.com/sbasestarter/bizinters/userinters"
)

type Manager interface {
	GetUser(ctx context.Context, userID uint64, tokenDataList map[string][]byte) (ds map[string]interface{}, err error)
}

func NewManager() Manager {
	return &managerImpl{}
}

type managerImpl struct {
}

func (impl *managerImpl) GetUser(ctx context.Context, userID uint64, tokenDataList map[string][]byte) (ds map[string]interface{}, err error) {
	err = json.Unmarshal(tokenDataList[userinters.AuthMethodNameAnonymous], &ds)
	if err != nil {
		return
	}

	return
}
