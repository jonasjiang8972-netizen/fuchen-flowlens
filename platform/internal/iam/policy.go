package iam

import (
	"fmt"
	"strings"
	"unicode"
)

// Policy is the configurable security policy, edited by the system
// administrator. Defaults follow common MLPS level 3 / financial practice;
// Validate enforces floors so the policy cannot be weakened below them.
type Policy struct {
	PasswordMinLength    int `json:"password_min_length"`      // >= 8
	PasswordMinClasses   int `json:"password_min_classes"`     // of upper/lower/digit/symbol, 3..4
	PasswordHistory      int `json:"password_history"`         // previous passwords that cannot be reused
	PasswordMaxAgeDays   int `json:"password_max_age_days"`    // forced change interval, 1..90
	LockoutThreshold     int `json:"lockout_threshold"`        // failed logins before lock, 3..10
	LockoutMinutes       int `json:"lockout_minutes"`          // >= 10
	SessionIdleMinutes   int `json:"session_idle_minutes"`     // 5..30
	SessionMaxHours      int `json:"session_max_hours"`        // 1..12
	AccountInactiveDays  int `json:"account_inactive_days"`    // disable after no login, 0 = off
	AuditRetentionDays   int `json:"audit_retention_days"`     // >= 180 (网络安全法: >= 6 months)
	LoginRatePerIPMinute int `json:"login_rate_per_ip_minute"` // login attempts per source IP per minute
}

func DefaultPolicy() Policy {
	return Policy{
		PasswordMinLength:    8,
		PasswordMinClasses:   3,
		PasswordHistory:      5,
		PasswordMaxAgeDays:   90,
		LockoutThreshold:     5,
		LockoutMinutes:       30,
		SessionIdleMinutes:   15,
		SessionMaxHours:      8,
		AccountInactiveDays:  90,
		AuditRetentionDays:   180,
		LoginRatePerIPMinute: 20,
	}
}

// Validate rejects policies weaker than the compliance floor.
func (p Policy) Validate() error {
	checks := []struct {
		ok  bool
		msg string
	}{
		{p.PasswordMinLength >= 8 && p.PasswordMinLength <= 64, "口令最小长度须在 8–64 之间"},
		{p.PasswordMinClasses >= 3 && p.PasswordMinClasses <= 4, "口令须至少包含 3 类字符（大写、小写、数字、特殊字符）"},
		{p.PasswordHistory >= 3 && p.PasswordHistory <= 24, "禁止重复使用的历史口令数须在 3–24 之间"},
		{p.PasswordMaxAgeDays >= 1 && p.PasswordMaxAgeDays <= 90, "口令有效期须在 1–90 天之间"},
		{p.LockoutThreshold >= 3 && p.LockoutThreshold <= 10, "登录失败锁定阈值须在 3–10 次之间"},
		{p.LockoutMinutes >= 10 && p.LockoutMinutes <= 1440, "锁定时长须在 10–1440 分钟之间"},
		{p.SessionIdleMinutes >= 5 && p.SessionIdleMinutes <= 30, "会话空闲超时须在 5–30 分钟之间"},
		{p.SessionMaxHours >= 1 && p.SessionMaxHours <= 12, "会话最长有效期须在 1–12 小时之间"},
		{p.AccountInactiveDays == 0 || (p.AccountInactiveDays >= 30 && p.AccountInactiveDays <= 365), "长期未登录停用天数须为 0（关闭）或 30–365"},
		{p.AuditRetentionDays >= 180, "审计日志保留期不得少于 180 天"},
		{p.LoginRatePerIPMinute >= 5 && p.LoginRatePerIPMinute <= 600, "单 IP 每分钟登录次数须在 5–600 之间"},
	}
	for _, c := range checks {
		if !c.ok {
			return fmt.Errorf("%s", c.msg)
		}
	}
	return nil
}

// CheckPassword validates a candidate password against the policy. It does
// not check history; the service does that against stored hashes.
func (p Policy) CheckPassword(password, username string) error {
	if len([]rune(password)) < p.PasswordMinLength {
		return fmt.Errorf("口令长度至少 %d 位", p.PasswordMinLength)
	}
	if len(password) > 72 {
		return fmt.Errorf("口令长度不能超过 72 字节")
	}
	var upper, lower, digit, symbol bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsLower(r):
			lower = true
		case unicode.IsDigit(r):
			digit = true
		case unicode.IsSpace(r):
			return fmt.Errorf("口令不能包含空白字符")
		default:
			symbol = true
		}
	}
	classes := 0
	for _, b := range []bool{upper, lower, digit, symbol} {
		if b {
			classes++
		}
	}
	if classes < p.PasswordMinClasses {
		return fmt.Errorf("口令须至少包含大写字母、小写字母、数字、特殊字符中的 %d 类", p.PasswordMinClasses)
	}
	if username != "" && strings.Contains(strings.ToLower(password), strings.ToLower(username)) {
		return fmt.Errorf("口令不能包含用户名")
	}
	return nil
}
