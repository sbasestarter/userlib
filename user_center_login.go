package userlib

import (
	"fmt"
	"time"

	"github.com/sbasestarter/bizinters/userinters"
)

type authForUserPolicy struct {
	userinters.AuthForUserPolicy
	UniqueID uint64
	StartAt  time.Time
}

func (impl *userCenterImpl) loginDataKey(id uint64) string {
	return fmt.Sprintf("login:data:%d", id)
}

func (impl *userCenterImpl) storeLoginData(d *authForUserPolicy) {
	impl.dataCache.Set(impl.loginDataKey(d.UniqueID), d, impl.loginDataCacheDuration)
}

func (impl *userCenterImpl) loadLoginData(id uint64) *authForUserPolicy {
	i, ok := impl.dataCache.Get(impl.loginDataKey(id))
	if !ok {
		return nil
	}

	d, ok := i.(*authForUserPolicy)
	if !ok {
		return nil
	}

	return d
}

func (impl *userCenterImpl) delLoginData(id uint64) {
	impl.dataCache.Delete(impl.loginDataKey(id))
}
