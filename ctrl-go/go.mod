module github.com/xwkpkp/proxy-guard/ctrl-go

// x/net 固定 v0.38.0：修复 CVE-2025-22870 / GHSA-qxp5-gwg8-xv66
//（HTTP proxy bypass via IPv6 zone IDs）。勿升级到需要 go 1.26 工具链的版本。
go 1.23.0

require (
	golang.org/x/net v0.38.0
	gopkg.in/yaml.v3 v3.0.1
)
