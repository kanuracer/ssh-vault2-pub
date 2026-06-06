package main

import (
	"github.com/tomatome/grdp/client"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/plugin"
)

const rdpStatusEvent = "rdp:status"

// rdpEngineControl is the backend control-plane surface used by Wails-exposed
// AppService methods.  Keeping the service on this interface makes the current
// grdp adapter replaceable by the native in-process RDP engine without changing
// the frontend API or event names.
type rdpEngineControl interface {
	Login() error
	Close()
	OnReady(func())
	OnSuccess(func())
	OnClose(func())
	OnError(func(error))
	OnBitmap(func([]client.Bitmap))
	MouseMove(x, y int)
	MouseDown(button, x, y int)
	MouseUp(button, x, y int)
	MouseWheel(delta, x, y int)
	KeyDown(scancode int, code string)
	KeyUp(scancode int, code string)
	TypeText(text string)
	SetClipboardTextProvider(func() string)
	SetClipboardFileProvider(func() []plugin.ClipboardFile)
	SetClipboardFileServedCallback(func(index int, complete bool))
	RefreshClipboard()
	SetAudioSink(func(plugin.RDPSNDAudioChunk))
}

var _ rdpEngineControl = (*client.Client)(nil)

func newRDPClientEngine(addr, user, password string, width, height int) rdpEngineControl {
	setting := client.NewSetting()
	setting.Width = width
	setting.Height = height
	setting.LogLevel = glog.ERROR
	return client.NewClient(addr, user, password, client.TC_RDP, setting)
}
