package jwtplus

// jwt配置类，
type Config struct {
	key      []byte
	duration int64
	ipValid  bool
	owner    string
}

// 创建配置实例对象
func NewConfig(key []byte) *Config {
	return &Config{
		key:      key,
		duration: 600,
		ipValid:  false,
		owner:    "xl_kit",
	}
}

// 默认配置实例对象
var defaultConfig *Config

func init() {
	defaultConfig = NewConfig([]byte("xl_kit@xl_kit"))
}
