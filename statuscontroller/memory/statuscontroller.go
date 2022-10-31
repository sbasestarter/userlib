package memory

import (
	"context"
	"strconv"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/sbasestarter/bizinters/userinters"
)

func NewStatusController() userinters.StatusController {
	return &statusControllerImpl{
		dataCache: cache.New(time.Minute, time.Minute),
	}
}

type statusControllerImpl struct {
	dataCache *cache.Cache
}

func (impl *statusControllerImpl) IsTokenBanned(_ context.Context, id uint64) (ok bool, _ error) {
	_, ok = impl.dataCache.Get(impl.tokenID(id))

	return
}

func (impl *statusControllerImpl) BanToken(_ context.Context, id uint64, expireAt int64) error {
	var d time.Duration

	if expireAt == 0 {
		d = cache.NoExpiration
	} else if time.Now().Unix() >= expireAt {
		return nil
	}

	impl.dataCache.Set(impl.tokenID(id), true, d)

	return nil
}

func (impl *statusControllerImpl) tokenID(id uint64) string {
	return strconv.FormatUint(id, 16)
}
