package userlib

import (
	"context"
	"crypto/md5" // nolint: gosec
	"time"

	"github.com/godruoyi/go-snowflake"
	"github.com/sbasestarter/bizinters/userinters"
	"github.com/sgostarter/i/commerr"
	"github.com/sgostarter/i/l"
)

func NewUserCenter(tokenSecKey string, policy userinters.Policy, userStatus userinters.StatusController,
	authingDataStorage userinters.AuthingDataStorage, logger l.Wrapper) userinters.UserCenter {
	if logger == nil {
		logger = l.NewNopLoggerWrapper()
	}

	if policy == nil || userStatus == nil || authingDataStorage == nil {
		logger.Fatal("invalid interfaces")
	}

	// nolint: gosec
	h := md5.Sum([]byte(tokenSecKey))

	return &userCenterImpl{
		policy:                 policy,
		userStatus:             userStatus,
		authingDataStorage:     authingDataStorage,
		logger:                 logger.WithFields(l.StringField(l.ClsKey, "userCenterImpl")),
		loginDataCacheDuration: time.Minute,
		tokenSecKey:            h[:],
	}
}

type userCenterImpl struct {
	policy             userinters.Policy
	userStatus         userinters.StatusController
	authingDataStorage userinters.AuthingDataStorage
	logger             l.Wrapper

	loginDataCacheDuration time.Duration
	tokenSecKey            interface{}
}

func (impl *userCenterImpl) authenticatorsV2M(authenticators []userinters.Authenticator) (
	authenticatorsMap map[string]userinters.Authenticator, methods []string, err error) {
	authenticatorsMap = make(map[string]userinters.Authenticator)

	for _, authenticator := range authenticators {
		if authenticator == nil || authenticator.GetMethodName() == "" {
			continue
		}

		if _, ok := authenticatorsMap[authenticator.GetMethodName()]; ok {
			err = commerr.ErrAlreadyExists

			return
		}

		methods = append(methods, authenticator.GetMethodName())
		authenticatorsMap[authenticator.GetMethodName()] = authenticator
	}

	return
}

func (impl *userCenterImpl) doAuth(ctx context.Context, d *userinters.AuthingData, authenticatorsMap map[string]userinters.Authenticator, logger l.Wrapper) (
	nextRequiredMethods []string, err error) {
	var deadCheckLoop int
NEXT:
	if deadCheckLoop > 10 {
		err = commerr.ErrCanceled

		return
	}

	requiredMethods, err := impl.policy.RequireAuthMethod(ctx, &d.AuthForUserPolicy)
	if err != nil {
		return
	}

	if len(requiredMethods) == 0 {
		if d.UserID == 0 {
			logger.Error("AuthedButNoUserID")

			err = commerr.ErrInternal
		}

		return
	}

	var authenticators []userinters.Authenticator

	for _, method := range requiredMethods {
		if authenticator, ok := authenticatorsMap[method]; ok {
			authenticators = append(authenticators, authenticator)
		}
	}

	if len(authenticators) == 0 {
		nextRequiredMethods = requiredMethods

		return
	}

	var verified bool

	for _, authenticator := range authenticators {
		uid, tokenData, ok, _ := authenticator.Verify(ctx)
		if ok {
			if uid != 0 {
				if d.UserID == 0 {
					d.UserID = uid
				} else if d.UserID != uid {
					err = commerr.ErrInternal

					return
				}
			}

			verified = true

			d.VerifiedMethods = append(d.VerifiedMethods, &userinters.VerifiedMethodWithTokenData{
				MethodName: authenticator.GetMethodName(),
				TokenData:  tokenData,
			})

			break
		}
	}

	if !verified {
		err = commerr.ErrReject

		return
	}

	deadCheckLoop++

	goto NEXT
}

func (impl *userCenterImpl) Login(ctx context.Context, request *userinters.LoginRequest) (resp *userinters.LoginResponse, err error) {
	if request == nil {
		err = commerr.ErrInvalidArgument

		return
	}

	authenticatorsMap, methods, err := impl.authenticatorsV2M(request.Authenticators)
	if err != nil {
		return
	}

	var d *userinters.AuthingData

	if request.ContinueID != 0 {
		d, _ = impl.authingDataStorage.Load(ctx, request.ContinueID)
	}

	if d == nil {
		d = &userinters.AuthingData{
			AuthForUserPolicy: userinters.AuthForUserPolicy{
				SupportedMethods: methods,
			},
			UniqueID: snowflake.ID(),
			StartAt:  time.Now(),
		}
	}

	nextRequiredMethods, err := impl.doAuth(ctx, d, authenticatorsMap, impl.logger)
	if err != nil {
		return
	}

	if len(nextRequiredMethods) > 0 {
		resp = &userinters.LoginResponse{
			Status:            userinters.LoginStatusNeedMoreAuthenticator,
			RequiredOrMethods: nextRequiredMethods,
			ContinueID:        d.UniqueID,
		}

		_ = impl.authingDataStorage.Store(ctx, d, impl.loginDataCacheDuration)

		return
	}

	_ = impl.authingDataStorage.Delete(ctx, d.UniqueID)

	methodDataList := make(map[string][]byte)

	for _, method := range d.VerifiedMethods {
		if len(method.TokenData) == 0 {
			continue
		}

		methodDataList[method.MethodName] = method.TokenData
	}

	token, err := impl.generateToken(d.UserID, d.UniqueID, methodDataList, request.TokenLiveDuration)

	if err != nil {
		return
	}

	resp = &userinters.LoginResponse{
		Status: userinters.LoginStatusSuccess,
		UserID: d.UserID,
		Token:  token,
	}

	return
}

func (impl *userCenterImpl) Logout(ctx context.Context, token string) (err error) {
	info, expireAt, err := impl.parseToken(token)
	if err != nil {
		return
	}

	err = impl.userStatus.BanToken(ctx, info.UniqueID, expireAt)

	return
}

func (impl *userCenterImpl) CheckToken(ctx context.Context, token string, renewToken bool) (newToken string,
	uid uint64, tokenDataList map[string][]byte, err error) {
	info, _, err := impl.parseToken(token)
	if err != nil {
		return
	}

	banned, err := impl.userStatus.IsTokenBanned(ctx, info.UniqueID)
	if err != nil {
		impl.logger.WithFields(l.ErrorField(err)).Error("IsTokenBanned")

		return
	}

	if banned {
		impl.logger.WithFields(l.StringField("token", token), l.UInt64Field("uniqueID", info.UniqueID)).
			Warn("TokenHasBanned")

		err = commerr.ErrReject

		return
	}

	uid = info.UserID

	tokenDataList = info.AuthenticatorMethodDataList

	if renewToken {
		newToken, err = impl.generateToken(info.UserID, snowflake.ID(), info.AuthenticatorMethodDataList,
			info.TokenLiveDuration)
	}

	return
}
