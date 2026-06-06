package plugin

import (
	"bytes"
	"encoding/binary"

	"github.com/tomatome/grdp/core"
)

const (
	RDPGFX_DVC_CHANNEL_NAME = "Microsoft::Windows::RDS::Graphics"

	drdynvcCmdCreate     = 0x01
	drdynvcCmdDataFirst  = 0x02
	drdynvcCmdData       = 0x03
	drdynvcCmdClose      = 0x04
	drdynvcCmdCapability = 0x05

	drdynvcCBIDOneByte   = 0x00
	drdynvcCBIDTwoBytes  = 0x01
	drdynvcCBIDFourBytes = 0x02
)

type DynamicChannelSender interface {
	SendDynamic(data []byte) error
}

type DynamicChannelTransport interface {
	DynamicChannelName() string
	OnOpen(sender DynamicChannelSender)
	ProcessDynamic(data []byte)
}

type DrdynvcState struct {
	CapabilityVersion   uint16
	CapabilityConfirmed bool
	OpenChannels        map[uint32]string
}

type DrdynvcClient struct {
	sender              core.ChannelSender
	capabilityVersion   uint16
	capabilityConfirmed bool
	dynamics            map[string]DynamicChannelTransport
	open                map[uint32]DynamicChannelTransport
	openNames           map[uint32]string
	fragments           map[uint32][]byte
	fragmentExpected    map[uint32]uint32
}

func NewDrdynvcClient() *DrdynvcClient {
	return &DrdynvcClient{
		dynamics:         make(map[string]DynamicChannelTransport),
		open:             make(map[uint32]DynamicChannelTransport),
		openNames:        make(map[uint32]string),
		fragments:        make(map[uint32][]byte),
		fragmentExpected: make(map[uint32]uint32),
	}
}

func (c *DrdynvcClient) GetType() (string, uint32) {
	return DRDYNVC_SVC_CHANNEL_NAME, uint32(StaticVirtualChannels[DRDYNVC_SVC_CHANNEL_NAME])
}

func (c *DrdynvcClient) Sender(sender core.ChannelSender) { c.sender = sender }

func (c *DrdynvcClient) RegisterDynamic(t DynamicChannelTransport) {
	if t == nil || t.DynamicChannelName() == "" {
		return
	}
	c.dynamics[t.DynamicChannelName()] = t
}

func (c *DrdynvcClient) HasDynamic(name string) bool {
	_, ok := c.dynamics[name]
	return ok
}

func (c *DrdynvcClient) State() DrdynvcState {
	m := make(map[uint32]string, len(c.openNames))
	for id, name := range c.openNames {
		m[id] = name
	}
	return DrdynvcState{CapabilityVersion: c.capabilityVersion, CapabilityConfirmed: c.capabilityConfirmed, OpenChannels: m}
}

var _ ChannelTransport = (*DrdynvcClient)(nil)

func (c *DrdynvcClient) Process(s []byte) {
	if len(s) == 0 {
		return
	}
	cmd := s[0] >> 4
	sp := (s[0] & 0x0c) >> 2
	cbid := s[0] & 0x03
	p := s[1:]
	channelID, used, ok := readDrdynvcChannelID(cbid, p)
	if cmd != drdynvcCmdCapability {
		if !ok {
			return
		}
		p = p[used:]
	}
	switch cmd {
	case drdynvcCmdCapability:
		c.processCapability(p)
	case drdynvcCmdCreate:
		c.processCreate(channelID, p)
	case drdynvcCmdData:
		c.processData(channelID, p)
	case drdynvcCmdDataFirst:
		c.processDataFirst(channelID, sp, p)
	case drdynvcCmdClose:
		delete(c.open, channelID)
		delete(c.openNames, channelID)
		delete(c.fragments, channelID)
		delete(c.fragmentExpected, channelID)
	}
}

func (c *DrdynvcClient) processCapability(p []byte) {
	if len(p) < 3 {
		return
	}
	version := binary.LittleEndian.Uint16(p[1:3])
	c.capabilityVersion = version
	c.capabilityConfirmed = true
	resp := []byte{byte(drdynvcCmdCapability << 4), 0}
	resp = binary.LittleEndian.AppendUint16(resp, version)
	c.send(resp)
}

func (c *DrdynvcClient) processCreate(channelID uint32, p []byte) {
	nameBytes := p
	if i := bytes.IndexByte(p, 0); i >= 0 {
		nameBytes = p[:i]
	}
	name := string(nameBytes)
	status := uint32(0)
	var ch DynamicChannelTransport
	if opened, ok := c.dynamics[name]; ok {
		ch = opened
		c.open[channelID] = ch
		c.openNames[channelID] = name
	} else {
		status = 0xc0000001
	}
	resp := []byte{byte(drdynvcCmdCreate<<4) | drdynvcCBIDOneByte, byte(channelID)}
	resp = binary.LittleEndian.AppendUint32(resp, status)
	c.send(resp)
	if status == 0 && ch != nil {
		ch.OnOpen(drdynvcDynamicSender{client: c, channelID: channelID})
	}
}

func (c *DrdynvcClient) processData(channelID uint32, p []byte) {
	ch := c.open[channelID]
	if ch == nil {
		return
	}
	if frag := c.fragments[channelID]; frag != nil {
		p = append(frag, p...)
		if expected := c.fragmentExpected[channelID]; expected > 0 && uint32(len(p)) < expected {
			c.fragments[channelID] = p
			return
		}
		delete(c.fragments, channelID)
		delete(c.fragmentExpected, channelID)
	}
	ch.ProcessDynamic(p)
}

func (c *DrdynvcClient) processDataFirst(channelID uint32, sp byte, p []byte) {
	expected, used, ok := readDrdynvcLength(sp, p)
	if !ok {
		return
	}
	data := append([]byte(nil), p[used:]...)
	if uint32(len(data)) >= expected {
		if ch := c.open[channelID]; ch != nil {
			ch.ProcessDynamic(data)
		}
		return
	}
	c.fragments[channelID] = data
	c.fragmentExpected[channelID] = expected
}

func (c *DrdynvcClient) send(p []byte) {
	if c.sender != nil {
		_, _ = c.sender.SendToChannel(DRDYNVC_SVC_CHANNEL_NAME, p)
	}
}

type drdynvcDynamicSender struct {
	client    *DrdynvcClient
	channelID uint32
}

func (s drdynvcDynamicSender) SendDynamic(data []byte) error {
	p := []byte{byte(drdynvcCmdData<<4) | drdynvcCBIDOneByte, byte(s.channelID)}
	p = append(p, data...)
	s.client.send(p)
	return nil
}

func readDrdynvcChannelID(cbid byte, p []byte) (uint32, int, bool) {
	switch cbid {
	case drdynvcCBIDOneByte:
		if len(p) < 1 {
			return 0, 0, false
		}
		return uint32(p[0]), 1, true
	case drdynvcCBIDTwoBytes:
		if len(p) < 2 {
			return 0, 0, false
		}
		return uint32(binary.LittleEndian.Uint16(p[:2])), 2, true
	case drdynvcCBIDFourBytes:
		if len(p) < 4 {
			return 0, 0, false
		}
		return binary.LittleEndian.Uint32(p[:4]), 4, true
	default:
		return 0, 0, false
	}
}

func readDrdynvcLength(cbid byte, p []byte) (uint32, int, bool) {
	return readDrdynvcChannelID(cbid, p)
}
