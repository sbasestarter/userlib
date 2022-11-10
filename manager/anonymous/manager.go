package anonymous

import (
	"context"

	"github.com/sbasestarter/bizinters/userinters"
)

type Manager interface {
	GetUser(ctx context.Context, userID uint64, tokenDataList map[string]string) (userName string, err error)
}

func NewManager() Manager {
	return &managerImpl{}
}

type managerImpl struct {
}

func (impl *managerImpl) GetUser(ctx context.Context, userID uint64, tokenDataList map[string]string) (userName string, err error) {
	userName = tokenDataList[userinters.AuthMethodNameAnonymous]

	return
}
