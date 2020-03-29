package jwtplus

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type MapClaims map[string]interface{}

// 自定义Claims类
type customClaims struct {
	*jwt.StandardClaims
	mapClaims MapClaims
}

func newClaims(conf *Config, userClaim MapClaims) *customClaims {
	c := &customClaims{
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Unix() + conf.duration,
			Issuer:    conf.owner,
		},
		mapClaims: userClaim,
	}
	return c
}
