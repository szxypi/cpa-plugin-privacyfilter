module github.com/rheodev/cpa-plugin-privacyfilter

go 1.26.0

require (
	github.com/router-for-me/CLIProxyAPI/v7 v7.2.155
	github.com/sirupsen/logrus v1.9.4
	golang.org/x/sys v0.47.0
	gopkg.in/yaml.v3 v3.0.1
	privacyfilter v0.0.0-20260609060647-64b8de3c2060
)

require (
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	github.com/tidwall/sjson v1.2.5 // indirect
)

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/tidwall/gjson v1.18.0
)

replace privacyfilter => github.com/packyme/privacy-filter v0.0.0-20260609060647-64b8de3c2060
