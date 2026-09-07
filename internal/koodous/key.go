package koodous

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// KeychainService is where the token is looked for on macOS.
const KeychainService = "developer.koodous.com"

// Token finds the Koodous developer token: the environment first, then the
// macOS keychain so it need not sit in cleartext in a client's config file.
//
// The token is generated in the Developers area of the Koodous account
// settings, not on signup.
func Token() (string, error) {
	if t := strings.TrimSpace(os.Getenv("KOODOUS_TOKEN")); t != "" {
		return t, nil
	}
	if runtime.GOOS == "darwin" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "security", "find-generic-password",
			"-s", KeychainService, "-w").Output()
		if err == nil {
			if t := strings.TrimSpace(string(out)); t != "" {
				return t, nil
			}
		}
	}
	return "", fmt.Errorf("no Koodous token: set KOODOUS_TOKEN.\n" +
		"Generate one in the Developers area of your account settings at https://koodous.com\n" +
		"On macOS it can instead be stored in the keychain under the service name " + KeychainService)
}
