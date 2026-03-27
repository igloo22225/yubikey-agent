// Copyright 2020 Google LLC
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

//go:build !darwin
// +build !darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/twpayne/go-pinentry-minimal/pinentry"
)

func getPIN(serial uint32, retries int) (string, error) {
	// check for WSL
	powershell, err := exec.LookPath(wslPathToPowershell)
	if err == nil {
		return getPINWSL(powershell, serial, retries)
	}

	client, err := pinentry.NewClient(
		pinentry.WithBinaryNameFromGnuPGAgentConf(),
		pinentry.WithGPGTTY(),
		pinentry.WithTitle("yubikey-agent PIN Prompt"),
		pinentry.WithDesc(fmt.Sprintf("YubiKey serial number: %d (%d tries remaining)", serial, retries)),
		pinentry.WithPrompt("Please enter your PIN:"),
		// Enable opt-in external PIN caching (in the OS keychain).
		// https://gist.github.com/mdeguzis/05d1f284f931223624834788da045c65#file-info-pinentry-L324
		pinentry.WithOption(pinentry.OptionAllowExternalPasswordCache),
		pinentry.WithKeyInfo(fmt.Sprintf("--yubikey-id-%d", serial)),
	)
	if err != nil {
		return "", err
	}
	defer client.Close()

	pin, _, err := client.GetPIN()
	return pin, err
}

func getPINWSL(powershell string, serial uint32, retries int) (string, error) {
	psCmd := `Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'yubikey-agent PIN prompt'
$form.Size = New-Object System.Drawing.Size(340,180)
$form.StartPosition = 'CenterScreen'
$form.MaximizeBox = 0;
$form.MinimizeBox = 0;
$form.TopMost = 1

$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(80,100)
$okButton.Size = New-Object System.Drawing.Size(80,23)
$okButton.Text = 'OK'
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $okButton
$form.Controls.Add($okButton)

$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(160,100)
$cancelButton.Size = New-Object System.Drawing.Size(80,23)
$cancelButton.Text = 'Cancel'
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $cancelButton
$form.Controls.Add($cancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(300,20)
$label.Text = 'YubiKey serial number: %d (%d tries remaining)'
$form.Controls.Add($label)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,40)
$label.Size = New-Object System.Drawing.Size(300,20)
$label.Text = 'Please enter your PIN:'
$form.Controls.Add($label)

$textBox = New-Object System.Windows.Forms.TextBox
$textBox.Location = New-Object System.Drawing.Point(10,60)
$textBox.Size = New-Object System.Drawing.Size(300,20)
$textBox.MaxLength = 8
$textBox.TextAlign = 2 # center
$textBox.PasswordChar = '*'

$form.Controls.Add($textBox)
$form.Topmost = $true
$form.Add_Shown({$textBox.Select()})

$result = $form.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $textBox.Text
    $x
}
else
{
	exit 1
}`
	psCmd = fmt.Sprintf(psCmd, serial, retries)
	cmd := wslGeneratePowershellCmd(powershell, psCmd)
	pin, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(pin)), nil
}
