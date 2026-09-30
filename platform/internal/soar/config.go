package soar

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// FromEnv builds the guardrail policy and connector list from environment
// variables. A connector is enabled by setting its primary variable. Secrets
// come only from the environment and are never stored or returned by the API.
//
//	FLOWLENS_SOAR_KONG_URL, FLOWLENS_SOAR_KONG_TOKEN
//	FLOWLENS_SOAR_APISIX_URL, FLOWLENS_SOAR_APISIX_KEY
//	FLOWLENS_SOAR_NGINX_DENY_FILE, FLOWLENS_SOAR_NGINX_RELOAD_CMD
//	FLOWLENS_SOAR_WEBHOOK_URL, FLOWLENS_SOAR_WEBHOOK_SECRET
//	FLOWLENS_SOAR_ALIYUN_WAF_ACCESS_KEY_ID / _ACCESS_KEY_SECRET / _INSTANCE_ID /
//	  _TEMPLATE_ID / _REGION / _ENDPOINT
//
// Policy: FLOWLENS_SOAR_DRY_RUN, _ALLOW_PRIVATE, _PROTECTED_CIDRS,
// _DEFAULT_TTL, _MAX_TTL (Go durations, e.g. 2h), _MAX_BLOCKS_PER_HOUR.
func FromEnv(getenv func(string) string) (Policy, []Adapter, error) {
	p := DefaultPolicy()
	var errs []string

	p.DryRun = getenv("FLOWLENS_SOAR_DRY_RUN") == "true"
	p.AllowPrivate = getenv("FLOWLENS_SOAR_ALLOW_PRIVATE") == "true"
	for _, c := range strings.Split(getenv("FLOWLENS_SOAR_PROTECTED_CIDRS"), ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if ip := net.ParseIP(c); ip != nil && ip.To4() != nil {
				c += "/32"
			} else if ip != nil {
				c += "/128"
			}
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			errs = append(errs, fmt.Sprintf("FLOWLENS_SOAR_PROTECTED_CIDRS: %q 无效", c))
			continue
		}
		p.ProtectedNets = append(p.ProtectedNets, n)
	}
	for name, dst := range map[string]*time.Duration{"FLOWLENS_SOAR_DEFAULT_TTL": &p.DefaultTTL, "FLOWLENS_SOAR_MAX_TTL": &p.MaxTTL} {
		if v := getenv(name); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil || d < time.Minute {
				errs = append(errs, fmt.Sprintf("%s: %q 不是有效时长（如 30m、2h，至少 1m）", name, v))
				continue
			}
			*dst = d
		}
	}
	if v := getenv("FLOWLENS_SOAR_MAX_BLOCKS_PER_HOUR"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			errs = append(errs, fmt.Sprintf("FLOWLENS_SOAR_MAX_BLOCKS_PER_HOUR: %q 必须是正整数", v))
		} else {
			p.MaxBlocksPerHour = n
		}
	}
	if p.DefaultTTL > p.MaxTTL {
		errs = append(errs, "FLOWLENS_SOAR_DEFAULT_TTL 不能大于 FLOWLENS_SOAR_MAX_TTL")
	}

	var adapters []Adapter
	if u := getenv("FLOWLENS_SOAR_KONG_URL"); u != "" {
		adapters = append(adapters, NewKong(u, getenv("FLOWLENS_SOAR_KONG_TOKEN")))
	}
	if u := getenv("FLOWLENS_SOAR_APISIX_URL"); u != "" {
		if getenv("FLOWLENS_SOAR_APISIX_KEY") == "" {
			errs = append(errs, "FLOWLENS_SOAR_APISIX_URL 已设置，但缺少 FLOWLENS_SOAR_APISIX_KEY")
		} else {
			adapters = append(adapters, NewAPISIX(u, getenv("FLOWLENS_SOAR_APISIX_KEY")))
		}
	}
	if f := getenv("FLOWLENS_SOAR_NGINX_DENY_FILE"); f != "" {
		adapters = append(adapters, NewNginx(f, getenv("FLOWLENS_SOAR_NGINX_RELOAD_CMD")))
	}
	if u := getenv("FLOWLENS_SOAR_WEBHOOK_URL"); u != "" {
		if getenv("FLOWLENS_SOAR_WEBHOOK_SECRET") == "" {
			errs = append(errs, "FLOWLENS_SOAR_WEBHOOK_URL 已设置，但缺少 FLOWLENS_SOAR_WEBHOOK_SECRET（请求必须签名）")
		} else {
			adapters = append(adapters, NewWebhook(u, getenv("FLOWLENS_SOAR_WEBHOOK_SECRET")))
		}
	}
	if id := getenv("FLOWLENS_SOAR_ALIYUN_WAF_ACCESS_KEY_ID"); id != "" {
		c := AliyunConfig{
			AccessKeyID: id, AccessKeySecret: getenv("FLOWLENS_SOAR_ALIYUN_WAF_ACCESS_KEY_SECRET"),
			InstanceID: getenv("FLOWLENS_SOAR_ALIYUN_WAF_INSTANCE_ID"), TemplateID: getenv("FLOWLENS_SOAR_ALIYUN_WAF_TEMPLATE_ID"),
			Region: getenv("FLOWLENS_SOAR_ALIYUN_WAF_REGION"), Endpoint: getenv("FLOWLENS_SOAR_ALIYUN_WAF_ENDPOINT"),
		}
		if c.AccessKeySecret == "" || c.InstanceID == "" || c.TemplateID == "" {
			errs = append(errs, "阿里云 WAF 需要同时设置 ACCESS_KEY_SECRET、INSTANCE_ID 和 TEMPLATE_ID（IP 黑名单防护模板 ID）")
		} else {
			adapters = append(adapters, NewAliyunWAF(c))
		}
	}

	if len(errs) > 0 {
		return p, adapters, fmt.Errorf("联动系统配置错误：%s", strings.Join(errs, "；"))
	}
	return p, adapters, nil
}
