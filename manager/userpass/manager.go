package userpass

import (
	"context"

	inters "github.com/sbasestarter/bizinters/userinters/userpass"
	"github.com/sgostarter/i/commerr"
	"github.com/sgostarter/libeasygo/crypt"
)

type Manager interface {
	inters.UserPasswordVerifier

	Register(ctx context.Context, userName, password string) (userID uint64, err error)
	GetUser(ctx context.Context, userID uint64) (user *User, err error)
	GetUserByUserName(ctx context.Context, userName string) (user *User, err error)

	UpdateUserExData(ctx context.Context, userID uint64, key string, val interface{}) error
	UpdateUserAllExData(ctx context.Context, userID uint64, exData map[string]interface{}) error
}

func NewManager(passwordSecret string, model inters.UserPasswordModel) Manager {
	return &managerImpl{
		model:          model,
		passwordSecret: passwordSecret,
	}
}

type managerImpl struct {
	model          inters.UserPasswordModel
	passwordSecret string
}

func (impl *managerImpl) passEncrypt(content string) (string, error) {
	return crypt.HMacSHa256(impl.passwordSecret, content)
}

func (impl *managerImpl) Verify(ctx context.Context, user, password string) (userID uint64, ok bool, err error) {
	u, err := impl.model.GetUserByUserName(ctx, user)
	if err != nil {
		return
	}

	ePassword, err := impl.passEncrypt(password)
	if err != nil {
		return
	}

	if u.Password != ePassword {
		return
	}

	userID = u.ID
	ok = true

	return
}

func (impl *managerImpl) Register(ctx context.Context, userName, password string) (userID uint64, err error) {
	if userName == "" {
		err = commerr.ErrInvalidArgument

		return
	}

	ePassword, err := impl.passEncrypt(password)
	if err != nil {
		return
	}

	user, err := impl.model.AddUser(ctx, userName, ePassword)
	if err != nil {
		return
	}

	userID = user.ID

	return
}

func (impl *managerImpl) GetUser(ctx context.Context, userID uint64) (user *User, err error) {
	u, err := impl.model.GetUser(ctx, userID)
	if err != nil {
		return
	}

	user = &User{
		ID:       u.ID,
		UserName: u.UserName,
		CreateAt: u.CreateAt,
		ExData:   u.ExData,
	}

	return
}

func (impl *managerImpl) GetUserByUserName(ctx context.Context, userName string) (user *User, err error) {
	u, err := impl.model.GetUserByUserName(ctx, userName)
	if err != nil {
		return
	}

	user = &User{
		ID:       u.ID,
		UserName: u.UserName,
		CreateAt: u.CreateAt,
		ExData:   u.ExData,
	}

	return
}

func (impl *managerImpl) UpdateUserExData(ctx context.Context, userID uint64, key string, val interface{}) error {
	return impl.model.UpdateUserExData(ctx, userID, key, val)
}

func (impl *managerImpl) UpdateUserAllExData(ctx context.Context, userID uint64, exData map[string]interface{}) error {
	return impl.model.UpdateUserAllExData(ctx, userID, exData)
}
