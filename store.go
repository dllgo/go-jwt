package jwtplus

import (
	redisplus "github.com/dllgo/go-redis"
	"github.com/dllgo/go-utils"
)

// Storer 黑名单存储接口
var Storer = NewStore()

func NewStore() *Store {
	return &Store{}
}

// Store buntdb存储
type Store struct {
}

func (a *Store) tokenKey(token string) string {
	return "doudou:token:" + utils.MD5HashString(token)
}

// 放入令牌，指定到期时间
func (a *Store) Set(tokenString string, expiration int64) (bool, error) {
	return redisplus.RedisClient.SetEx(a.tokenKey(tokenString), "1", expiration)
}

// 检查令牌是否存在
func (a *Store) Check(tokenString string) (bool, error) {
	return redisplus.RedisClient.Exists(a.tokenKey(tokenString))
}
