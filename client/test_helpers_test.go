package main

import "testing"

func withTempConfig(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	t.Setenv("HOME", d)
	t.Setenv("XDG_CONFIG_HOME", d)
	t.Setenv("APPDATA", d)
	return d
}

func unlockTestVault(t *testing.T, s *AppService) {
	t.Helper()
	if _, err := s.LocalVaultUnlock("local-test-passphrase"); err != nil {
		t.Fatalf("LocalVaultUnlock: %v", err)
	}
}
