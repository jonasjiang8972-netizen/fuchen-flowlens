package detector

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
)

type CollectMode string

const (
	ModeEBPF      CollectMode = "ebpf"
	ModeDPDK      CollectMode = "dpdk"
	ModeGatewayLog CollectMode = "gateway_log"
	ModeVPCFlow   CollectMode = "vpc_flow"
	ModePcap      CollectMode = "pcap"
	ModeAuto      CollectMode = "auto"
)

type Environment struct {
	IsKubernetes   bool
	HasCilium      bool
	HasDPDK        bool
	HasTAPPort     bool
	GWLogPath      string
	GWLogFormat    string
	CloudProvider  string
	HasCloudCreds  bool
	HasPcapPerm    bool
	KernelVersion  string
	OS             string
	Arch           string
}

func DetectEnvironment() *Environment {
	env := &Environment{
		OS:            runtime.GOOS,
		Arch:           runtime.GOARCH,
		KernelVersion: getKernelVersion(),
	}

	env.IsKubernetes = detectKubernetes()
	env.HasCilium = detectCilium()
	env.HasDPDK = detectDPDKSupport()
	env.HasTAPPort = detectTAPPort()
	env.GWLogPath, env.GWLogFormat = detectGatewayLog()
	env.CloudProvider, env.HasCloudCreds = detectCloudProvider()
	env.HasPcapPerm = detectPcapPermission()

	return env
}

func AutoDetect(env *Environment) CollectMode {
	log := logger.L()

	if env.IsKubernetes {
		if env.HasCilium {
			log.Info("Auto-detected: K8s + Cilium environment, using eBPF mode")
			return ModeEBPF
		}
		log.Info("Auto-detected: K8s environment, using eBPF mode")
		return ModeEBPF
	}

	if env.HasDPDK && env.HasTAPPort {
		log.Info("Auto-detected: DPDK + SPAN/TAP available, using DPDK mode")
		return ModeDPDK
	}

	if env.GWLogPath != "" {
		log.Infof("Auto-detected: Gateway log at %s, using Gateway Log mode", env.GWLogPath)
		return ModeGatewayLog
	}

	if env.HasCloudCreds {
		log.Infof("Auto-detected: Cloud provider %s with credentials, using VPC Flow mode", env.CloudProvider)
		return ModeVPCFlow
	}

	if env.HasPcapPerm {
		log.Info("Auto-detected: Using pcap fallback mode")
		return ModePcap
	}

	log.Warn("No suitable collection mode detected, falling back to pcap")
	return ModePcap
}

func detectKubernetes() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return true
	}
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
		return true
	}
	return false
}

func detectCilium() bool {
	cmd := exec.Command("cilium", "status", "--brief")
	if err := cmd.Run(); err == nil {
		return true
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		out, _ := exec.Command("bpftool", "map", "list").Output()
		if strings.Contains(string(out), "cilium") {
			return true
		}
	}
	return false
}

func detectDPDKSupport() bool {
	if _, err := os.Stat("/dev/hugepages"); err == nil {
		return true
	}
	return false
}

func detectTAPPort() bool {
	out, err := exec.Command("ip", "link", "show").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "tap") || strings.Contains(string(out), "mirror")
}

func detectGatewayLog() (string, string) {
	paths := []struct {
		path   string
		format string
	}{
		{"/var/log/kong/access.log", "json"},
		{"/var/log/apisix/access.log", "json"},
		{"/var/log/nginx/access.log", "nginx"},
		{"/var/log/envoy/access.log", "envoy"},
	}

	for _, p := range paths {
		if _, err := os.Stat(p.path); err == nil {
			return p.path, p.format
		}
	}
	return "", ""
}

func detectCloudProvider() (string, bool) {
	if os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID") != "" {
		return "aliyun", true
	}
	if os.Getenv("TENCENTCLOUD_SECRET_ID") != "" {
		return "tencent", true
	}
	if os.Getenv("AWS_ACCESS_KEY_ID") != "" {
		return "aws", true
	}
	if os.Getenv("AZURE_CLIENT_ID") != "" {
		return "azure", true
	}
	return "", false
}

func detectPcapPermission() bool {
	if os.Geteuid() != 0 {
		return false
	}
	return true
}

func getKernelVersion() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func (e *Environment) String() string {
	parts := []string{
		fmt.Sprintf("OS=%s", e.OS),
		fmt.Sprintf("Arch=%s", e.Arch),
		fmt.Sprintf("Kernel=%s", e.KernelVersion),
	}
	if e.IsKubernetes {
		parts = append(parts, "K8s=true")
	}
	if e.HasCilium {
		parts = append(parts, "Cilium=true")
	}
	if e.HasDPDK {
		parts = append(parts, "DPDK=true")
	}
	if e.GWLogPath != "" {
		parts = append(parts, fmt.Sprintf("GWLog=%s", e.GWLogPath))
	}
	if e.CloudProvider != "" {
		parts = append(parts, fmt.Sprintf("Cloud=%s", e.CloudProvider))
	}
	return strings.Join(parts, " ")
}
