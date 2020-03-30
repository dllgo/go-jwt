package jwtplus

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	// 默认情况下从http请求的中读取的key名称
	header string = "Authorization"
)

type MapClaims map[string]interface{}

// jwt操作
type Handle struct {
	*Config
	lock *sync.RWMutex
}

// 生成token
func (r *Handle) TokenGenerator(data interface{}) (string, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	//
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	if v, ok := data.(map[string]interface{}); ok {
		for key, value := range v {
			claims[key] = value
		}
	}
	expire := time.Now().Unix() + r.duration
	claims["exp"] = expire
	claims["orig_iat"] = time.Now().Unix()
	tokenString, err := token.SignedString(r.key)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// 根据token校验token是否有效
// 如果token有效，则返回true，否则返回false
func (r *Handle) TokenValid(token string) bool {
	_, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) {
		return r.key, nil
	})
	return err == nil
}

// 解析token，返回claims信息，
// 如果token无效，则error将会展示错误信息，
// 如果token有效，customClaims将会返回连接用户的信息
func (r *Handle) TokenParse(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod("HS256") != t.Method {
			return nil, errors.New("invalid signing algorithm")
		}
		return r.key, nil
	})
}

//  销毁令牌
// 临时存放到redis ，每次校验判断是否在redis中，如果在表示token无效
func (r *Handle) TokenDestroy(token string) error {
	jtoken, err := r.TokenParse(token)
	if err != nil {
		return err
	}
	claims := jtoken.Claims.(jwt.MapClaims)
	exp := int64(claims["exp"].(float64))
	expired := exp - time.Now().Unix()
	if expired <= 0 {
		expired = 0
	}
	_, err = Storer.Set(token, expired)
	if err != nil {
		return err
	}
	return nil
}

// ExtractClaimsFromToken help to extract the JWT claims from token
func (r *Handle) ExtractClaimsFromToken(token *jwt.Token) MapClaims {
	if token == nil {
		return make(MapClaims)
	}
	claims := MapClaims{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}
	return claims
}
func (r *Handle) ParseToken(token string) (MapClaims, error) {
	rclaims, err := r.TokenParse(token)
	if err != nil {
		return nil, errors.New("parase with claims failed.")
	}

	exists, err := Storer.Check(token)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New("invalid token.")
	}
	return r.ExtractClaimsFromToken(rclaims), nil
}

// 从Http的请求中获取Token，校验token是否有效
// 如果token有效，则返回true，如果无效，则返回false
func (r *Handle) ValidHttp(req *http.Request) bool {
	token := r.httpToken(req)
	return r.TokenValid(token)
}

// 从http请求中获取token，然后解析token
func (r *Handle) ParseHttp(req *http.Request) (MapClaims, error) {
	token := r.httpToken(req)
	return r.ParseToken(token)
}

// 从http中获取token
func (r *Handle) httpToken(req *http.Request) string {
	token := r.tokenFromHeader(req, header)
	if token == "" {
		token = r.tokenFromCookie(req, header)
	}
	if token == "" {
		token = r.tokenFromParam(req, header)
	}
	return token
}

func (r *Handle) tokenFromHeader(req *http.Request, key string) string {
	authHeader := req.Header.Get(key)
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if !(len(parts) == 2 && parts[0] == "Bearer") {
		return ""
	}

	return parts[1]
}

func (r *Handle) tokenFromCookie(req *http.Request, key string) string {
	cookie, _ := req.Cookie(key)
	if cookie.Value == "" {
		return ""
	}
	return cookie.Value
}

func (r *Handle) tokenFromParam(req *http.Request, key string) string {
	req.ParseForm()
	token := req.FormValue(key)
	if token == "" {
		return ""
	}
	return token
}

func (r *Handle) SetKey(key []byte) *Handle {
	r.lock.Lock()
	r.key = key
	r.lock.Unlock()
	return r
}

// 创建jwtHandle实例对象
func NewHandle(conf *Config) *Handle {
	if conf == nil {
		handleLock.RLock()
		conf = defaultConfig
		conf.key = []byte("dllgo-go-jwt")
		handleLock.RUnlock()
	}
	return &Handle{
		Config: conf,
		lock:   new(sync.RWMutex),
	}
}
