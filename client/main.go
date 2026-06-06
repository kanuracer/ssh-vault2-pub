package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

func init() {
	application.RegisterEvent[SSHDataPayload]("ssh:data")
	application.RegisterEvent[SessionState]("ssh:status")
	application.RegisterEvent[SessionState](rdpStatusEvent)
}

func main() {
	svc := NewAppService()
	app := application.New(application.Options{
		Name:        "ssh-vault2",
		Description: "SSH/SFTP desktop client",
		Services:    []application.Service{application.NewService(svc)},
		Assets:      application.AssetOptions{Handler: application.AssetFileServerFS(assets)},
		Mac:         application.MacOptions{ApplicationShouldTerminateAfterLastWindowClosed: true},
	})
	svc.setApp(app)
	wp := loadWindowPrefs()
	opts := application.WebviewWindowOptions{
		Title:            "ssh-vault2",
		Width:            1380,
		Height:           820,
		MinWidth:         1120,
		MinHeight:        700,
		BackgroundColour: application.NewRGB(8, 9, 18),
		URL:              "/",
	}
	if wp.Valid {
		opts.InitialPosition = application.WindowXY
		opts.X = wp.X
		opts.Y = wp.Y
		opts.Width = wp.Width
		opts.Height = wp.Height
	}
	win := app.Window.NewWithOptions(opts)
	win.OnWindowEvent(events.Common.WindowDidMove, func(_ *application.WindowEvent) { saveWindowPrefsFromWindow(win) })
	win.OnWindowEvent(events.Common.WindowDidResize, func(_ *application.WindowEvent) { saveWindowPrefsFromWindow(win) })
	win.OnWindowEvent(events.Common.WindowClosing, func(_ *application.WindowEvent) { saveWindowPrefsFromWindow(win); _ = svc.CloseAllSessions() })
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
