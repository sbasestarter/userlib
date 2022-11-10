package userlib

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/sgostarter/libeasygo/commerr"
)

type TokenUserInfo struct {
	UserID            uint64
	UniqueID          uint64
	TokenLiveDuration time.Duration
}

type UserClaims struct {
	TokenUserInfo
	jwt.StandardClaims
}

func (impl *userCenterImpl) generateToken(userID, uniqueID uint64, tokenKeepDuration time.Duration) (token string, err error) {
	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, UserClaims{
		TokenUserInfo: TokenUserInfo{
			UserID:            userID,
			UniqueID:          uniqueID,
			TokenLiveDuration: tokenKeepDuration,
		},
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenKeepDuration).Unix(),
		},
	}).SignedString(impl.tokenSecKey)

	return
}

func (impl *userCenterImpl) parseToken(token string) (info *TokenUserInfo, expireAt int64, err error) {
	var claims UserClaims

	tokenObj, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return impl.tokenSecKey, nil
	})
	if err != nil {
		return
	}

	if userClaims, ok := tokenObj.Claims.(*UserClaims); ok && tokenObj.Valid {
		info = &userClaims.TokenUserInfo
		expireAt = userClaims.ExpiresAt
	} else {
		err = commerr.ErrUnauthenticated
	}

	return
}
