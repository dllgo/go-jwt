package jwtplus

import (
	"net/http"
	"sync"
)

var (
	handleLock    = new(sync.RWMutex)
	defaultHandle *Handle
)

// 校验http请求是否有有效的授权认证信息
func ValidTokenHttp(req *http.Request) bool {
	handleLock.RLock()
	defer handleLock.RUnlock()
	return defaultHandle.ValidHttp(req)
}

// 从http请求中获取用户信息，如果用户已经获得授权，则返回用户信息，error为nil，
// 如果用户没有授权信息，或者授权信息已经过期，则errors为错误信息
func ParseTokenHttp(req *http.Request) (MapClaims, error) {
	handleLock.RLock()
	defer handleLock.RUnlock()
	return defaultHandle.ParseHttp(req)
}

// 修改默认的Handle方法
func SetHandle(jwtHandle *Handle) {
	handleLock.Lock()
	defaultHandle = jwtHandle
	handleLock.Unlock()
}

// 生成授权信息
func GenToken(data interface{}) (string, error) {
	handleLock.RLock()
	defer handleLock.RUnlock()
	return defaultHandle.TokenGenerator(data)
}

// 校验token信息是否有效
func ValidToken(token string) bool {
	handleLock.RLock()
	defer handleLock.RUnlock()
	return defaultHandle.TokenValid(token)
}

//解析token是否有效，如果有效，则返回userdata实例对象
func ParseToken(token string) (MapClaims, error) {
	handleLock.RLock()
	defer handleLock.RUnlock()
	return defaultHandle.ParseToken(token)
}

//销毁令牌
func DestroyToken(token string) error {
	handleLock.RLock()
	defer handleLock.RUnlock()
	return defaultHandle.TokenDestroy(token)
}

func init() {
	defaultHandle = NewHandle(defaultConfig)
}
