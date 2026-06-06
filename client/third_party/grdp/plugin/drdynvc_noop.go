package plugin

type NoopDynamicChannel struct{ name string }

func NewNoopDynamicChannel(name string) *NoopDynamicChannel      { return &NoopDynamicChannel{name: name} }
func (c *NoopDynamicChannel) DynamicChannelName() string         { return c.name }
func (c *NoopDynamicChannel) OnOpen(sender DynamicChannelSender) {}
func (c *NoopDynamicChannel) ProcessDynamic(data []byte)         {}

var _ DynamicChannelTransport = (*NoopDynamicChannel)(nil)
