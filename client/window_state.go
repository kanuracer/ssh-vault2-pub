package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/wailsapp/wails/v3/pkg/application"
)

type WindowPrefs struct {
	X      int  `json:"x"`
	Y      int  `json:"y"`
	Width  int  `json:"width"`
	Height int  `json:"height"`
	Valid  bool `json:"valid"`
}

func windowPrefsPath() (string, error) {
	d, err := configDir()
	if err != nil { return "", err }
	return filepath.Join(d, "window.json"), nil
}

func loadWindowPrefs() WindowPrefs {
	p, err := windowPrefsPath(); if err != nil { return WindowPrefs{} }
	b, err := os.ReadFile(p); if err != nil { return WindowPrefs{} }
	var w WindowPrefs
	if json.Unmarshal(cleanJSONBytes(b), &w) != nil { return WindowPrefs{} }
	if w.Width < 900 || w.Height < 600 { return WindowPrefs{} }
	return w
}

func saveWindowPrefsFromWindow(w *application.WebviewWindow) {
	if w == nil || w.IsMinimised() || w.IsFullscreen() { return }
	b := w.Bounds()
	if b.Width < 900 || b.Height < 600 { return }
	p, err := windowPrefsPath(); if err != nil { return }
	_ = os.MkdirAll(filepath.Dir(p), 0700)
	payload, _ := json.MarshalIndent(WindowPrefs{X:b.X, Y:b.Y, Width:b.Width, Height:b.Height, Valid:true}, "", "  ")
	_ = os.WriteFile(p, payload, 0600)
}
