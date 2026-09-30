package soar

import "context"

// Simulator is a connector that accepts everything and enforces nothing. It
// is registered only in demo mode, so the console shows the whole workflow
// without touching any real gateway.
type Simulator struct{}

func (Simulator) Name() string                                   { return "simulator" }
func (Simulator) Label() string                                  { return "演示（模拟，不产生真实封禁）" }
func (Simulator) Block(context.Context, Request) (string, error) { return "", nil }
func (Simulator) Unblock(context.Context, string, string) error  { return nil }
func (Simulator) Check(context.Context) error                    { return nil }
