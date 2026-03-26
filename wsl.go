package main

import (
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

const wslPathToPowershell = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"

var wslLastAttachedBusID = ""

func wslGeneratePowershellCmd(powershell string, cmd string) *exec.Cmd {
	return exec.Command(powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", cmd)
}

func wslFindAndAttachYubiKey() error {
	if wslLastAttachedBusID != "" {
		return nil
	}
	powershell, err := exec.LookPath(wslPathToPowershell)
	if err != nil {
		return nil // ignore if not WSL
	}
	psCmd := `usbipd list`
	cmd := wslGeneratePowershellCmd(powershell, psCmd)
	out, err := cmd.Output()
	if err != nil {
		return errors.New("WSL: failed to list USB devices")
	}
	raw := strings.Split(strings.ToLower(string(out)), "\n")
	busid := ""
	for _, line := range raw {
		if line == "Persisted:" {
			break
		}
		if strings.Contains(line, "usbccid") {
			if strings.Contains(line, "not shared") {
				continue
			}
			if strings.Contains(line, "attached") {
				busid = strings.Fields(line)[0]
				break
			}
			if strings.Contains(line, "shared") {
				busid = strings.Fields(line)[0]
				psCmd = `usbipd attach --wsl --busid %s`
				psCmd = fmt.Sprintf(psCmd, busid)
				cmd = wslGeneratePowershellCmd(powershell, psCmd)
				err = cmd.Run()
				if err != nil {
					return fmt.Errorf("WSL: failed to attach USB device (busid: %s)", busid)
				}
				wslLastAttachedBusID = busid
				time.Sleep(1 * time.Second) // wait for the device to be ready
				break
			}
		}
	}
	if busid == "" {
		return errors.New("WSL: no YubiKey shared or attached, please run `usbpid bind --force --busid <busid>` on Windows as administrator")
	}
	return nil
}

func wslDetachLastConnectedBusID() {
	if wslLastAttachedBusID == "" {
		return
	}
	powershell, err := exec.LookPath(wslPathToPowershell)
	if err != nil {
		return // ignore if not WSL
	}
	psCmd := `usbipd detach --busid %s`
	psCmd = fmt.Sprintf(psCmd, wslLastAttachedBusID)
	cmd := wslGeneratePowershellCmd(powershell, psCmd)
	err = cmd.Run()
	if err != nil {
		log.Printf("WSL: failed to detach USB device (busid: %s)\n", wslLastAttachedBusID)
	}
	wslLastAttachedBusID = ""
}
