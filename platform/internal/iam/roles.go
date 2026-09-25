// Package iam implements operator identity and access management: roles and
// permissions with separation of duties, password policy, login protection
// and server-side sessions.
package iam

// Role is an operator role. Every account has exactly one role, which keeps
// the three management duties (system, audit, security) in separate hands as
// GB/T 22239-2019 level 3 requires; there is no role that bypasses checks.
type Role string

const (
	// Management console (系统管理后台)
	RoleSysAdmin   Role = "sys_admin"   // 系统管理员: accounts, security policy, collectors, system settings
	RoleAuditAdmin Role = "audit_admin" // 审计管理员: audit trail only

	// API security platform (API 安全管理平台)
	RoleSecAdmin Role = "sec_admin" // 安全管理员: detection policy, alert disposal, asset ownership
	RoleAnalyst  Role = "analyst"   // 安全分析员: triage and disposal
	RoleViewer   Role = "viewer"    // 只读
)

// Permission is a single capability checked on an API route.
type Permission string

const (
	// Management console
	PermUserManage   Permission = "user.manage"
	PermPolicyManage Permission = "policy.manage"
	PermAgentManage  Permission = "agent.manage"
	PermSystemManage Permission = "system.manage"
	PermAuditRead    Permission = "audit.read"

	// API security platform
	PermSecurityRead Permission = "security.read"
	PermRuleManage   Permission = "rule.manage"
	PermAlertHandle  Permission = "alert.handle"
	PermAssetManage  Permission = "asset.manage"
)

// Console names which front end a role works in.
type Console string

const (
	ConsoleAdmin    Console = "admin"
	ConsoleSecurity Console = "security"
)

type RoleInfo struct {
	Role        Role         `json:"role"`
	Name        string       `json:"name"`
	Console     Console      `json:"console"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

var roles = []RoleInfo{
	{RoleSysAdmin, "系统管理员", ConsoleAdmin, "管理账号、安全策略、采集器和系统设置；不能查看审计日志，也不能操作 API 安全业务",
		[]Permission{PermUserManage, PermPolicyManage, PermAgentManage, PermSystemManage}},
	{RoleAuditAdmin, "审计管理员", ConsoleAdmin, "查询、校验和导出审计日志；不能做其他任何操作",
		[]Permission{PermAuditRead}},
	{RoleSecAdmin, "安全管理员", ConsoleSecurity, "配置检测策略、处置告警、管理资产归属",
		[]Permission{PermSecurityRead, PermRuleManage, PermAlertHandle, PermAssetManage}},
	{RoleAnalyst, "安全分析员", ConsoleSecurity, "研判和处置告警、认领资产；不能修改检测策略",
		[]Permission{PermSecurityRead, PermAlertHandle, PermAssetManage}},
	{RoleViewer, "只读用户", ConsoleSecurity, "查看 API 安全数据，不能做任何修改",
		[]Permission{PermSecurityRead}},
}

var permIndex = func() map[Role]map[Permission]bool {
	m := make(map[Role]map[Permission]bool)
	for _, r := range roles {
		m[r.Role] = make(map[Permission]bool)
		for _, p := range r.Permissions {
			m[r.Role][p] = true
		}
	}
	return m
}()

// Roles lists every role with its permissions, for the role matrix page.
func Roles() []RoleInfo {
	out := make([]RoleInfo, len(roles))
	copy(out, roles)
	return out
}

// ValidRole reports whether r is a known role.
func ValidRole(r Role) bool {
	_, ok := permIndex[r]
	return ok
}

// Can reports whether role r holds permission p.
func Can(r Role, p Permission) bool {
	return permIndex[r][p]
}

// ConsoleOf returns the console a role signs in to.
func ConsoleOf(r Role) Console {
	for _, info := range roles {
		if info.Role == r {
			return info.Console
		}
	}
	return ""
}

// PermissionsOf returns the permissions of role r.
func PermissionsOf(r Role) []Permission {
	for _, info := range roles {
		if info.Role == r {
			return append([]Permission(nil), info.Permissions...)
		}
	}
	return nil
}
