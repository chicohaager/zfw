// Package watchdog installs a systemd watchdog pair on the persistent root
// (/etc) so the daemon still starts when the in-sysext unit loses the
// boot-time multi-user.target race — a known ZimaOS sysext pitfall.
package watchdog

import (
	"context"
	"os"
	"os/exec"
	"time"
)

const (
	svcPath   = "/etc/systemd/system/zfw-ui-watchdog.service"
	timerPath = "/etc/systemd/system/zfw-ui-watchdog.timer"

	svcUnit = `[Unit]
Description=Start zfw-ui if the sysext unit was missed at boot
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'systemctl is-active --quiet zfw-ui.service || systemctl start zfw-ui.service'
`
	timerUnit = `[Unit]
Description=Ensure zfw-ui is running after the sysext overlay is merged
[Timer]
OnBootSec=20
[Install]
WantedBy=timers.target
`
)

// EnsureInstalled writes the watchdog units (if missing or changed) and
// enables the timer. Idempotent; safe to call on every daemon start.
func EnsureInstalled(logf func(string, ...any)) error {
	changed := false
	for path, content := range map[string]string{svcPath: svcUnit, timerPath: timerUnit} {
		if b, err := os.ReadFile(path); err != nil || string(b) != content {
			if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
				return err
			}
			changed = true
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if changed {
		_ = exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
	}
	if err := exec.CommandContext(ctx, "systemctl", "enable", "--now", "zfw-ui-watchdog.timer").Run(); err != nil {
		if logf != nil {
			logf("watchdog: enable timer: %v", err)
		}
		return err
	}
	return nil
}
