package normalizer

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jonasjiang8972-netizen/fuchen-flowlens/pkg/logger"
	"github.com/jonasjiang8972-netizen/fuchen-flowlens/shared"
)

type Normalizer struct {
	mu              sync.RWMutex
	pathPatterns    []*pathPattern
	staticPaths     map[string]string
}

type pathPattern struct {
	regex          *regexp.Regexp
	template       string
	paramNames     []string
	minConfidence  float64
}

func New() *Normalizer {
	n := &Normalizer{
		staticPaths: make(map[string]string),
	}
	n.initPatterns()
	return n
}

func (n *Normalizer) initPatterns() {
	n.pathPatterns = []*pathPattern{
		{
			regexp:         regexp.MustCompile(`^/([a-zA-Z0-9_-]+)/(\d+)(/|$)`),
			template:       "/$1/{id}$3",
			paramNames:     []string{"id"},
			minConfidence:  0.8,
		},
		{
			regexp:         regexp.MustCompile(`^/([a-zA-Z0-9_-]+)/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$)`),
			template:       "/$1/{uuid}$3",
			paramNames:     []string{"uuid"},
			minConfidence:  0.9,
		},
		{
			regexp:         regexp.MustCompile(`^/([a-zA-Z0-9_-]+)/(\d+)/([a-zA-Z0-9_-]+)/(\d+)(/|$)`),
			template:       "/$1/{id}/$3/{id}$5",
			paramNames:     []string{"id", "id"},
			minConfidence:  0.7,
		},
		{
			regexp:         regexp.MustCompile(`^/([a-zA-Z0-9_-]+)/([A-Z]{2,})(/|$)`),
			template:       "/$1/{enum}$3",
			paramNames:     []string{"enum"},
			minConfidence:  0.6,
		},
		{
			regexp:         regexp.MustCompile(`^/([a-zA-Z0-9_-]+)/(\d{14,})(/|$)`),
			template:       "/$1/{timestamp}$3",
			paramNames:     []string{"timestamp"},
			minConfidence:  0.7,
		},
	}
}

func (n *Normalizer) NormalizePath(rawPath string) (string, float64) {
	if rawPath == "" || rawPath == "/" {
		return rawPath, 1.0
	}

	n.mu.RLock()
	if normalized, ok := n.staticPaths[rawPath]; ok {
		n.mu.RUnlock()
		return normalized, 1.0
	}
	n.mu.RUnlock()

	for _, pattern := range n.pathPatterns {
		if matches := pattern.regex.FindStringSubmatch(rawPath); matches != nil {
			result := pattern.template
			for i, name := range pattern.paramNames {
				if i+1 < len(matches) {
					result = strings.Replace(result, "{"+name+"}", "{"+name+"}", 1)
				}
			}
			result = pattern.regex.ReplaceAllString(rawPath, n.replacement(pattern))
			n.mu.Lock()
			n.staticPaths[rawPath] = result
			n.mu.Unlock()
			return result, pattern.minConfidence
		}
	}

	return rawPath, 1.0
}

func (n *Normalizer) replacement(p *pathPattern) string {
	result := p.template
	for _, name := range p.paramNames {
		result = strings.Replace(result, "{"+name+"}", "$"+n.indexOf(p.paramNames, name), 1)
	}
	return result
}

func (n *Normalizer) indexOf(names []string, target string) string {
	for i, name := range names {
		if name == target {
			return strconv.Itoa(i + 1)
		}
	}
	return "1"
}

func (n *Normalizer) NormalizeEvent(evt *shared.APIEvent) *shared.APIEvent {
	if evt.Application.PathRaw != "" {
		normalized, confidence := n.NormalizePath(evt.Application.PathRaw)
		evt.Application.PathNormalized = normalized
		_ = confidence
	}

	if evt.Application.Method == "" {
		evt.Application.Method = "GET"
	}

	if evt.Application.ProtocolType == "" {
		evt.Application.ProtocolType = "REST"
	}

	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now()
	}

	if evt.Metadata.Env == "" {
		evt.Metadata.Env = "prod"
	}

	return evt
}

func (n *Normalizer) NormalizeBatch(events []*shared.APIEvent) []*shared.APIEvent {
	results := make([]*shared.APIEvent, 0, len(events))
	for _, evt := range events {
		normalized := n.NormalizeEvent(evt)
		results = append(results, normalized)
	}
	return results
}

func (n *Normalizer) GetStats() map[string]interface{} {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return map[string]interface{}{
		"cached_paths":   len(n.staticPaths),
		"pattern_count":  len(n.pathPatterns),
	}
}

func (n *Normalizer) AddCustomPattern(regexStr, template string, confidence float64) error {
	re, err := regexp.Compile(regexStr)
	if err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.pathPatterns = append(n.pathPatterns, &pathPattern{
		regex:         re,
		template:      template,
		minConfidence: confidence,
	})
	logger.L().Infof("Added custom path normalization pattern: %s -> %s", regexStr, template)
	return nil
}
