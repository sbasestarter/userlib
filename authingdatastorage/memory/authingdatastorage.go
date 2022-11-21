package memory

import (
	"context"
	"fmt"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/sbasestarter/bizinters/userinters"
	"github.com/sgostarter/i/commerr"
)

func NewMemoryAuthingDataStorage() userinters.AuthingDataStorage {
	return NewMemoryAuthingDataStorageEx("", nil)
}

func NewMemoryAuthingDataStorageEx(groupKey string, c *cache.Cache) userinters.AuthingDataStorage {
	if c == nil {
		c = cache.New(time.Minute, time.Minute)
	}

	return &memoryAuthingDataImpl{
		c:        c,
		groupKey: groupKey,
	}
}

type memoryAuthingDataImpl struct {
	c        *cache.Cache
	groupKey string
}

func (impl *memoryAuthingDataImpl) Store(ctx context.Context, d *userinters.AuthingData, expiration time.Duration) error {
	if d == nil {
		return commerr.ErrInvalidArgument
	}

	impl.c.Set(impl.key(d.UniqueID), d, expiration)

	return nil
}

func (impl *memoryAuthingDataImpl) Load(ctx context.Context, uniqueID uint64) (ad *userinters.AuthingData, err error) {
	i, ok := impl.c.Get(impl.key(uniqueID))
	if !ok {
		return
	}

	ad, _ = i.(*userinters.AuthingData)

	return
}

func (impl *memoryAuthingDataImpl) Delete(ctx context.Context, uniqueID uint64) error {
	impl.c.Delete(impl.key(uniqueID))

	return nil
}

func (impl *memoryAuthingDataImpl) key(uniqueID uint64) string {
	key := fmt.Sprintf("authing_data:%d", uniqueID)

	if impl.groupKey != "" {
		key = impl.groupKey + ":" + key
	}

	return key
}
