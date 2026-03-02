//go:build windows
// +build windows
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
	_ "embed"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func isAdmin() bool {
	var hToken windows.Token
	currentProcess := windows.CurrentProcess()

	// Open process token
	err := windows.OpenProcessToken(currentProcess, windows.TOKEN_QUERY, &hToken)
	if err != nil {
		return false
	}
	defer hToken.Close()

	// TokenElevation struct
	type TokenElevation struct {
		TokenIsElevated uint32
	}

	var elevation TokenElevation
	var retLen uint32

	err = windows.GetTokenInformation(
		hToken,
		windows.TokenElevationType,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&retLen,
	)
	if err != nil {
		return false
	}

	return elevation.TokenIsElevated != 0
}

var (
	modadvapi32         = windows.NewLazySystemDLL("advapi32.dll")
	procSetEntriesInAcl = modadvapi32.NewProc("SetEntriesInAclW")
)

// setEntriesInAcl calls the Windows API SetEntriesInAclW function.
func setEntriesInAcl(count uint32, pEntries *windows.EXPLICIT_ACCESS, oldAcl *windows.ACL, newAcl **windows.ACL) error {
	r1, _, err := procSetEntriesInAcl.Call(
		uintptr(count),
		uintptr(unsafe.Pointer(pEntries)),
		uintptr(unsafe.Pointer(oldAcl)),
		uintptr(unsafe.Pointer(newAcl)),
	)
	if r1 != 0 {
		return err
	}
	return nil
}

// lockRegistryKey denies full access to "Everyone" for the specified registry key path.
func lockRegistryKey(path string) error {
	// Open registry key with permissions to read control info and modify DACL.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return fmt.Errorf("failed to open key: %v", err)
	}
	defer key.Close()

	hKey := windows.Handle(key)

	// Retrieve current security info to comply with API usage (can be omitted if unused).
	_, err = windows.GetSecurityInfo(
		hKey,
		windows.SE_REGISTRY_KEY,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("failed to get security info: %v", err)
	}

	// Create a SID representing the "Everyone" group.
	everyoneSid, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return fmt.Errorf("failed to create SID: %v", err)
	}

	// Define explicit access rule denying all access to Everyone.
	ea := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.KEY_ALL_ACCESS,
		AccessMode:        windows.DENY_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			MultipleTrustee:          nil,
			MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
			TrusteeForm:              windows.TRUSTEE_IS_SID,
			TrusteeType:              windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue:             windows.TrusteeValue(uintptr(unsafe.Pointer(everyoneSid))),
		},
	}

	var newDACL *windows.ACL
	err = setEntriesInAcl(1, &ea, nil, &newDACL)
	if err != nil {
		return fmt.Errorf("failed to set entries in ACL: %v", err)
	}

	// Apply the new DACL to the registry key.
	err = windows.SetSecurityInfo(
		hKey,
		windows.SE_REGISTRY_KEY,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil,
		newDACL,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to set security info: %v", err)
	}

	return nil
}

func setEnableLUA() error {
	key, _, err := registry.CreateKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		registry.SET_VALUE,
	)
	if err != nil {
		return fmt.Errorf("failed to create/open key: %v", err)
	}
	defer key.Close()

	// EnableLUA = 1 (enable UAC)
	err = key.SetDWordValue("EnableLUA", 1)
	if err != nil {
		return fmt.Errorf("failed to set EnableLUA: %v", err)
	}
	return nil
}

func restartSystem() error {
	cmd := exec.Command("shutdown", "/r", "/t", "0")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	return cmd.Run()
}

var (
	moduser32       = windows.NewLazySystemDLL("user32.dll")
	procMessageBoxW = moduser32.NewProc("MessageBoxW")
)

func messageBox(text, title string, flags uintptr) int {
	ret, _, _ := procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(text))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(title))),
		flags,
	)
	return int(ret)
}

const (
	MB_YESNO        = 0x00000004
	MB_ICONWARNING  = 0x00000030
	MB_ICONINFO     = 0x00000040
	IDYES           = 6
)

// searchRegistryKey recursively searches for keys containing the search term
func searchRegistryKey(rootKey registry.Key, path string, searchTerm string, results *[]string, maxDepth int, currentDepth int) {
	if currentDepth > maxDepth {
		return
	}

	key, err := registry.OpenKey(rootKey, path, registry.ENUMERATE_SUB_KEYS|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer key.Close()

	// Check if current path contains search term
	if strings.Contains(strings.ToLower(path), strings.ToLower(searchTerm)) {
		*results = append(*results, path)
	}

	// Enumerate subkeys
	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return
	}

	for _, subkey := range subkeys {
		var newPath string
		if path == "" {
			newPath = subkey
		} else {
			newPath = path + `\` + subkey
		}

		// Check subkey name
		if strings.Contains(strings.ToLower(subkey), strings.ToLower(searchTerm)) {
			*results = append(*results, newPath)
		}

		// Recurse into subkey
		searchRegistryKey(rootKey, newPath, searchTerm, results, maxDepth, currentDepth+1)
	}
}

func findRegistryKeys(searchTerm string) []string {
	var results []string
	
	fmt.Printf("Searching for registry keys containing '%s'...\n", searchTerm)
	
	// Search in common locations
	searchRoots := []struct {
		key  registry.Key
		path string
		name string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE`, "HKLM\\SOFTWARE"},
		{registry.LOCAL_MACHINE, `SYSTEM`, "HKLM\\SYSTEM"},
		{registry.CURRENT_USER, `SOFTWARE`, "HKCU\\SOFTWARE"},
	}

	for _, root := range searchRoots {
		fmt.Printf("Searching in %s...\n", root.name)
		searchRegistryKey(root.key, root.path, searchTerm, &results, 5, 0)
	}

	return results
}

func main() {
	if !isAdmin() {
		fmt.Println("This program must be run as Administrator!")
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(0)
	}

	fmt.Println("Registry Key Search and Lock Tool")
	fmt.Println("==================================")
	fmt.Println()

	// Search for keys containing "avp1234"
	searchTerm := "avp1234"
	results := findRegistryKeys(searchTerm)

	if len(results) == 0 {
		fmt.Printf("No registry keys found containing '%s'\n", searchTerm)
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		os.Exit(0)
	}

	fmt.Printf("\nFound %d registry key(s) containing '%s':\n", len(results), searchTerm)
	for i, path := range results {
		fmt.Printf("%d. %s\n", i+1, path)
	}

	fmt.Println("\n==================================")
	fmt.Println("PLANNED ACTIONS:")
	fmt.Println("1. Enable UAC (EnableLUA = 1)")
	for _, path := range results {
		fmt.Printf("2. Lock registry key: HKLM\\%s\n", path)
	}
	fmt.Println("3. Restart system")
	fmt.Println("==================================")

	// Ask for confirmation via console
	fmt.Print("\nDo you want to proceed with these actions? (yes/no): ")
	var response string
	fmt.Scanln(&response)

	if strings.ToLower(strings.TrimSpace(response)) != "yes" {
		fmt.Println("Operation cancelled by user.")
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(0)
	}

	// Double confirmation via message box
	msg := fmt.Sprintf("You are about to:\n\n"+
		"1. Enable UAC\n"+
		"2. Lock %d registry key(s)\n"+
		"3. Restart the system\n\n"+
		"This action cannot be easily undone!\n\n"+
		"Are you absolutely sure?", len(results))

	result := messageBox(msg, "Final Confirmation", MB_YESNO|MB_ICONWARNING)
	if result != IDYES {
		fmt.Println("Operation cancelled by user.")
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		os.Exit(0)
	}

	// Execute actions
	fmt.Println("\nExecuting actions...")

	// 1. Set EnableLUA
	fmt.Println("Setting EnableLUA...")
	if err := setEnableLUA(); err != nil {
		fmt.Printf("Warning: Failed to set EnableLUA: %v\n", err)
	} else {
		fmt.Println("✓ EnableLUA set successfully")
	}

	// 2. Lock found registry keys
	for _, path := range results {
		fullPath := path
		fmt.Printf("Locking registry key: %s...\n", fullPath)
		if err := lockRegistryKey(fullPath); err != nil {
			fmt.Printf("Warning: Failed to lock %s: %v\n", fullPath, err)
		} else {
			fmt.Printf("✓ Locked %s successfully\n", fullPath)
		}
	}

	// 3. Restart system
	fmt.Println("\nRestarting system in 5 seconds...")
	fmt.Println("Press Ctrl+C to cancel...")
	
	for i := 5; i > 0; i-- {
		fmt.Printf("%d...\n", i)
		exec.Command("timeout", "/t", "1", "/nobreak").Run()
	}

	fmt.Println("Restarting now...")
	if err := restartSystem(); err != nil {
		fmt.Printf("Failed to restart system: %v\n", err)
		fmt.Println("Please restart manually.")
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
	}
}
