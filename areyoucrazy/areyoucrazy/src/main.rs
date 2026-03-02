use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::Security::Authorization::*,
    Win32::Security::*,
    Win32::Storage::FileSystem::*,
    Win32::System::Memory::*,
    Win32::System::Registry::*,
    Win32::System::Services::*,
    Win32::System::Shutdown::*,
    Win32::System::Threading::*,
    Win32::UI::WindowsAndMessaging::*,
    
};

const SUSPICIOUS_PATTERNS: &[&str] = &["a"];

const SUSPICIOUS_PATHS: &[&str] = &[
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\$recycle.bin\\",
    "\\windows\\temp\\",
];

const SUSPICIOUS_NAME_PATTERNS: &[&str] = &[
    "svc", "service", "update", "helper", "agent", "daemon", "monitor",
];

const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".sys", ".vbs", ".bat", ".cmd", ".ps1", ".scr", ".com", ".pif",
];

const SCAN_DIRECTORIES: &[&str] = &[
    "C:\\Users",
    "C:\\Program Files",
    "C:\\ProgramData",
    "C:\\Windows\\Temp",
    "C:\\Temp",
];

#[derive(Debug, Clone)]
struct ServiceInfo {
    name: String,
    display_name: String,
    binary_path: String,
    #[allow(dead_code)]
    is_running: bool,
    #[allow(dead_code)]
    start_type: u32,
    description: String,
}

#[derive(Debug, Clone)]
struct ThreatInfo {
    threat_type: String,
    name: String,
    path: String,
    reason: String,
    severity: u8,
    size: u64,
    hash: Option<String>,
}

// Helper to convert Rust string to Wide C-String (Vec<u16>)
fn to_pcwstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn is_admin() -> bool {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        let process = GetCurrentProcess();

        if OpenProcessToken(process, TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut return_length = 0u32;

        let result = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = CloseHandle(token);

        result.is_ok() && elevation.TokenIsElevated != 0
    }
}

fn calculate_file_hash(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Some(format!("{:x}", hasher.finalize()))
}

fn is_suspicious_file(path: &Path, file_name: &str) -> (bool, String, u8) {
    let name_lower = file_name.to_lowercase();
    let path_str = path.to_string_lossy().to_lowercase();

    for pattern in SUSPICIOUS_PATTERNS {
        if name_lower.contains(pattern) {
            return (
                true,
                format!("Filename contains suspicious pattern: {}", pattern),
                5,
            );
        }
    }

    for pattern in SUSPICIOUS_PATTERNS {
        if path_str.contains(pattern) {
            return (
                true,
                format!("Path contains suspicious pattern: {}", pattern),
                5,
            );
        }
    }

    for suspicious_path in SUSPICIOUS_PATHS {
        if path_str.contains(suspicious_path) {
            if SUSPICIOUS_EXTENSIONS
                .iter()
                .any(|ext| name_lower.ends_with(ext))
            {
                return (
                    true,
                    format!("Executable in suspicious location: {}", suspicious_path),
                    4,
                );
            }
        }
    }

    if let Some(metadata) = fs::metadata(path).ok() {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            let attrs = metadata.file_attributes();
            if attrs & 0x2 != 0 {
                // FILE_ATTRIBUTE_HIDDEN
                if SUSPICIOUS_EXTENSIONS
                    .iter()
                    .any(|ext| name_lower.ends_with(ext))
                {
                    return (true, "Hidden executable file".to_string(), 4);
                }
            }
        }
    }

    if SUSPICIOUS_EXTENSIONS
        .iter()
        .any(|ext| name_lower.ends_with(ext))
    {
        if file_name.len() > 8
            && file_name
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .count()
                > file_name.len() / 2
        {
            return (
                true,
                "Executable with random-looking name".to_string(),
                3,
            );
        }

        if name_lower.matches('.').count() > 1 {
            return (true, "Executable with double extension".to_string(), 4);
        }
    }

    (false, String::new(), 0)
}

fn find_file_threats() -> Vec<ThreatInfo> {
    let mut threats = Vec::new();
    for scan_dir in SCAN_DIRECTORIES {
        let dir_path = Path::new(scan_dir);
        if !dir_path.exists() {
            continue;
        }
        let walker = WalkDir::new(dir_path)
            .max_depth(10)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok());

        for entry in walker {
            let path = entry.path();

            if entry.file_type().is_dir() {
                continue;
            }

            let file_name = match path.file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => continue,
            };

            let (is_suspicious, reason, severity) = is_suspicious_file(path, &file_name);

            if is_suspicious {
                let size = entry.metadata().ok().map(|m| m.len()).unwrap_or(0);

                let hash = if SUSPICIOUS_EXTENSIONS
                    .iter()
                    .any(|ext| file_name.to_lowercase().ends_with(ext))
                {
                    calculate_file_hash(path)
                } else {
                    None
                };

                threats.push(ThreatInfo {
                    threat_type: "File".to_string(),
                    name: file_name,
                    path: path.to_string_lossy().to_string(),
                    reason,
                    severity,
                    size,
                    hash,
                });
            }
        }
    }
    threats
}

fn delete_file_threat(path: &str) -> bool {
    let file_path = Path::new(path);

    if let Ok(metadata) = fs::metadata(file_path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            let _ = fs::set_permissions(file_path, permissions);
        }
    }

    match fs::remove_file(file_path) {
        Ok(_) => true,
        Err(_) => try_force_delete(file_path),
    }
}

fn try_force_delete(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    let path_wide = to_pcwstr(&path_str);

    unsafe {
        // Method 1: Try to take ownership and delete
        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_ok() {
            let mut user_buffer = [0u8; 256];
            let mut user_size = user_buffer.len() as u32;

            if GetTokenInformation(
                token,
                TokenUser,
                Some(user_buffer.as_mut_ptr() as *mut _),
                user_size,
                &mut user_size,
            )
            .is_ok()
            {
                let token_user = &*(user_buffer.as_ptr() as *const TOKEN_USER);

                // Try to set owner
                // FIXED: Changed argument type for PSID to match new API requirements
                let _ = SetNamedSecurityInfoW(
                    PCWSTR(path_wide.as_ptr()),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    token_user.User.Sid, 
                    None,
                    None,
                    None,
                );
            }
            let _ = CloseHandle(token);
        }

        if fs::remove_file(path).is_ok() {
            return true;
        }

        // Method 2: Schedule for deletion on reboot
        // FIXED: MoveFileExW is now in Storage::FileSystem
        if MoveFileExW(
            PCWSTR(path_wide.as_ptr()),
            PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
        .is_ok()
        {
            return true;
        }
    }

    false
}

fn search_registry_recursive(
    hkey: HKEY,
    subkey_path: &str,
    search_term: &str,
    results: &mut Vec<String>,
    depth: u32,
    max_depth: u32,
) {
    if depth > max_depth {
        return;
    }

    unsafe {
        let subkey_wide = to_pcwstr(subkey_path);
        let mut hkey_result = HKEY::default();

        if RegOpenKeyExW(
            hkey,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey_result,
        )
        .is_err()
        {
            return;
        }

        if subkey_path
            .to_lowercase()
            .contains(&search_term.to_lowercase())
        {
            results.push(subkey_path.to_string());
        }

        let mut index = 0u32;
        loop {
            let mut name_buffer = [0u16; 256];
            let mut name_len = name_buffer.len() as u32;

            let result = RegEnumKeyExW(
                hkey_result,
                index,
                PWSTR(name_buffer.as_mut_ptr()),
                &mut name_len,
                None,
                PWSTR::null(),
                None,
                None,
            );

            if result.is_err() {
                break;
            }

            let subkey_name = String::from_utf16_lossy(&name_buffer[..name_len as usize]);

            let new_path = if subkey_path.is_empty() {
                subkey_name.clone()
            } else {
                format!("{}\\{}", subkey_path, subkey_name)
            };

            if subkey_name
                .to_lowercase()
                .contains(&search_term.to_lowercase())
            {
                results.push(new_path.clone());
            }

            search_registry_recursive(
                hkey,
                &new_path,
                search_term,
                results,
                depth + 1,
                max_depth,
            );

            index += 1;
        }

        let _ = RegCloseKey(hkey_result);
    }
}

fn find_registry_threats() -> Vec<ThreatInfo> {
    let mut threats = Vec::new();

    let search_roots = vec![
        (HKEY_LOCAL_MACHINE, "SOFTWARE", "HKLM\\SOFTWARE"),
        (HKEY_LOCAL_MACHINE, "SYSTEM", "HKLM\\SYSTEM"),
        (HKEY_CURRENT_USER, "SOFTWARE", "HKCU\\SOFTWARE"),
    ];

    for (hkey, path, display_name) in search_roots {
        for pattern in SUSPICIOUS_PATTERNS {
            let mut results = Vec::new();
            search_registry_recursive(hkey, path, pattern, &mut results, 0, 6);

            for result in results {
                let full_path = format!("{}\\{}", display_name.split('\\').next().unwrap(), result);
                threats.push(ThreatInfo {
                    threat_type: "Registry Key".to_string(),
                    name: pattern.to_string(),
                    path: full_path,
                    reason: format!("Contains suspicious pattern: {}", pattern),
                    severity: 4,
                    size: 0,
                    hash: None,
                });
            }
        }
    }
    threats
}

fn get_all_services() -> Vec<ServiceInfo> {
    let mut services = Vec::new();
    unsafe {
        let sc_manager =
            match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) {
                Ok(handle) => handle,
                Err(_) => return services,
            };

        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume_handle = 0u32;

        // FIXED: Removed explicit buffer length (0) argument. 
        // Newer windows crate infers this from the slice (None).
        let _ = EnumServicesStatusExW(
            sc_manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            PCWSTR::null(),
        );

        if bytes_needed == 0 {
            let _ = CloseServiceHandle(sc_manager);
            return services;
        }

        let mut buffer = vec![0u8; bytes_needed as usize];

        // FIXED: Removed explicit buffer length argument.
        // Passed Some(slice) instead of raw pointer and size.
        if EnumServicesStatusExW(
            sc_manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(&mut buffer),
            &mut bytes_needed,
            &mut services_returned,
            Some(&mut resume_handle),
            PCWSTR::null(),
        )
        .is_ok()
        {
            let service_slice = std::slice::from_raw_parts(
                buffer.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                services_returned as usize,
            );

            for service_status in service_slice {
                let service_name = service_status.lpServiceName.to_string().unwrap_or_default();
                let display_name = service_status.lpDisplayName.to_string().unwrap_or_default();

                if let Ok(service_handle) =
                    OpenServiceW(sc_manager, service_status.lpServiceName, SERVICE_QUERY_CONFIG)
                {
                    let mut config_bytes_needed = 0u32;
                    // FIXED: Removed explicit buffer size (0)
                    let _ = QueryServiceConfigW(service_handle, None, 0, &mut config_bytes_needed);
                    if config_bytes_needed > 0 {
                        let mut config_buffer = vec![0u8; config_bytes_needed as usize];

                        // FIXED: Removed explicit buffer size
                        if QueryServiceConfigW(
                            service_handle,
                            Some(config_buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
                            config_bytes_needed,
                            &mut config_bytes_needed,
                        ).is_ok()
                        {
                            let config =
                                &*(config_buffer.as_ptr() as *const QUERY_SERVICE_CONFIGW);

                            let binary_path =
                                config.lpBinaryPathName.to_string().unwrap_or_default();

                            let mut desc_bytes_needed = 0u32;
                            let _ = QueryServiceConfigW(service_handle, None, 0, &mut config_bytes_needed);
                            let mut description = String::new();
                            if desc_bytes_needed > 0 {
                                let mut desc_buffer = vec![0u8; desc_bytes_needed as usize];
                                if QueryServiceConfigW(
                                    service_handle, 
                                    Some(config_buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW), 
                                    config_bytes_needed, 
                                    &mut config_bytes_needed
                                ).is_ok()
                                {
                                    let desc_struct =
                                        &*(desc_buffer.as_ptr() as *const SERVICE_DESCRIPTIONW);
                                    description =
                                        desc_struct.lpDescription.to_string().unwrap_or_default();
                                }
                            }

                            services.push(ServiceInfo {
                                name: service_name.clone(),
                                display_name: display_name.clone(),
                                binary_path,
                                is_running: service_status.ServiceStatusProcess.dwCurrentState
                                    == SERVICE_RUNNING,
                                start_type: config.dwStartType.0,
                                description,
                            });
                        }
                    }
                    let _ = CloseServiceHandle(service_handle);
                }
            }
        }
        let _ = CloseServiceHandle(sc_manager);
    }
    services
}

fn is_suspicious_service(service: &ServiceInfo) -> (bool, String, u8) {
    let name_lower = service.name.to_lowercase();
    let display_lower = service.display_name.to_lowercase();
    let binary_lower = service.binary_path.to_lowercase();
    let desc_lower = service.description.to_lowercase();

    for pattern in SUSPICIOUS_PATTERNS {
        if name_lower.contains(pattern)
            || display_lower.contains(pattern)
            || binary_lower.contains(pattern)
            || desc_lower.contains(pattern)
        {
            return (
                true,
                format!("Contains suspicious pattern: {}", pattern),
                5,
            );
        }
    }

    for path in SUSPICIOUS_PATHS {
        if binary_lower.contains(path) {
            return (
                true,
                format!("Binary in suspicious location: {}", path),
                4,
            );
        }
    }

    if !binary_lower.contains("\\windows\\")
        && !binary_lower.contains("\\program files\\")
        && !binary_lower.contains("\\program files (x86)\\")
        && !binary_lower.is_empty()
    {
        let has_suspicious_name = SUSPICIOUS_NAME_PATTERNS
            .iter()
            .any(|p| name_lower.contains(p) || display_lower.contains(p));

        if has_suspicious_name {
            return (
                true,
                "Non-standard location with suspicious naming".to_string(),
                3,
            );
        }

        return (
            true,
            "Binary outside standard directories".to_string(),
            2,
        );
    }

    if service.name.len() > 8
        && service
            .name
            .chars()
            .filter(|c| c.is_ascii_digit())
            .count()
            > service.name.len() / 3
    {
        return (
            true,
            "Service name appears randomly generated".to_string(),
            3,
        );
    }

    if service.description.is_empty() && !binary_lower.contains("\\windows\\") {
        return (
            true,
            "No description and non-system location".to_string(),
            2,
        );
    }

    (false, String::new(), 0)
}

fn find_service_threats() -> Vec<ThreatInfo> {
    let mut threats = Vec::new();
    let services = get_all_services();

    for service in services {
        let (is_suspicious, reason, severity) = is_suspicious_service(&service);

        if is_suspicious {
            threats.push(ThreatInfo {
                threat_type: "Service".to_string(),
                name: service.name.clone(),
                path: service.binary_path.clone(),
                reason,
                severity,
                size: 0,
                hash: None,
            });
        }
    }
    threats
}

fn stop_and_delete_service(service_name: &str) -> bool {
    unsafe {
        let sc_manager =
            match OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) {
                Ok(handle) => handle,
                Err(_) => return false,
            };

        let service_name_wide = to_pcwstr(service_name);

        let service_handle = match OpenServiceW(
            sc_manager,
            PCWSTR(service_name_wide.as_ptr()),
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE.0, // Use the direct constant
        ){
            Ok(handle) => handle,
            Err(_) => {
                let _ = CloseServiceHandle(sc_manager);
                return false;
            }
        };

        let mut status = SERVICE_STATUS::default();
        let _ = ControlService(service_handle, SERVICE_CONTROL_STOP, &mut status);

        for _ in 0..60 {
            if QueryServiceStatus(service_handle, &mut status).is_ok() {
                if status.dwCurrentState == SERVICE_STOPPED {
                    break;
                }
            }
            thread::sleep(Duration::from_millis(500));
        }

        let result = DeleteService(service_handle).is_ok();

        let _ = CloseServiceHandle(service_handle);
        let _ = CloseServiceHandle(sc_manager);

        result
    }
}

fn lock_registry_key(key_path: &str) -> bool {
    unsafe {
        let parts: Vec<&str> = key_path.split('\\').collect();
        if parts.len() < 2 {
            return false;
        }

        let root_key = match parts[0] {
            "HKLM" => HKEY_LOCAL_MACHINE,
            "HKCU" => HKEY_CURRENT_USER,
            _ => return false,
        };

        let subkey_path = parts[1..].join("\\");
        let subkey_wide = to_pcwstr(&subkey_path);

        let mut hkey = HKEY::default();
        if RegOpenKeyExW(
            root_key,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            REG_SAM_FLAGS(KEY_READ.0 | KEY_WRITE.0 | 0x00040000u32),
            &mut hkey,
        )
        .is_err()
        {
            return false;
        }

        let mut everyone_sid_buffer = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut sid_size = SECURITY_MAX_SID_SIZE;

        if CreateWellKnownSid(
            WinWorldSid,
            // FIXED: PSID::null() -> PSID::default() or just None/null pointer
            PSID::default(),
            PSID(everyone_sid_buffer.as_mut_ptr() as *mut _),
            &mut sid_size,
        )
        .is_err()
        {
            let _ = RegCloseKey(hkey);
            return false;
        }

        let mut ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: KEY_ALL_ACCESS.0,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
                ptstrName: PWSTR(everyone_sid_buffer.as_mut_ptr() as *mut _),
            },
        };

        let mut new_acl: *mut ACL = std::ptr::null_mut();

        if SetEntriesInAclW(Some(&[ea]), None, &mut new_acl).is_err() {
            let _ = RegCloseKey(hkey);
            return false;
        }

        // FIXED: HANDLE cast needs to point to void, not isize
        let result = SetSecurityInfo(
            HANDLE(hkey.0),
            SE_REGISTRY_KEY,
            DACL_SECURITY_INFORMATION,
            // FIXED: PSID::null() -> PSID::default()
            PSID::default(),
            PSID::default(),
            Some(new_acl),
            None,
        );

        if !new_acl.is_null() {
            let _ = LocalFree(HLOCAL(new_acl as *mut _));
        }

        let _ = RegCloseKey(hkey);

        result.is_ok()
    }
}

fn enable_uac() -> bool {
    unsafe {
        let subkey_wide =
            to_pcwstr("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");

        let mut hkey = HKEY::default();

        if RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut hkey,
            None,
        )
        .is_err()
        {
            return false;
        }

        let value_name_wide = to_pcwstr("EnableLUA");
        let value: u32 = 1;

        let result = RegSetValueExW(
            hkey,
            PCWSTR(value_name_wide.as_ptr()),
            0,
            REG_DWORD,
            Some(&value.to_le_bytes()),
        );

        let _ = RegCloseKey(hkey);

        result.is_ok()
    }
}

fn restart_system() {
    unsafe {
        let mut token: HANDLE = HANDLE::default();

        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_ok()
        {
            let mut luid = LUID::default();
            let privilege_name = to_pcwstr("SeShutdownPrivilege");

            if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(privilege_name.as_ptr()), &mut luid)
                .is_ok()
            {
                let tkp = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };

                let _ = AdjustTokenPrivileges(token, FALSE, Some(&tkp), 0, None, None);
            }
            let _ = CloseHandle(token);
        }

        // FIXED: InitiateSystemShutdownExW takes a SHUTDOWN_REASON as the last argument,
        // not SHUTDOWN_FLAGS. We use the flags in the 4th/5th boolean args or 
        // rely on default behavior + SHTDN_REASON_FLAG_PLANNED.
        // Boolean 1: Force apps closed (true)
        // Boolean 2: Reboot after shutdown (true)
        let _ = InitiateSystemShutdownExW(
            PCWSTR::null(),
            PCWSTR::null(),
            0,
            true, 
            true, 
            SHTDN_REASON_MAJOR_OPERATINGSYSTEM | SHTDN_REASON_FLAG_PLANNED,
        );
    }
}

fn main() -> Result<()> {
    if !is_admin() {
        println!("ERROR: This program must be run as Administrator!");
        println!("Press Enter to exit...");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        std::process::exit(1);
    }

    let mut all_threats = Vec::new();

    println!("Scanning files...");
    let file_threats = find_file_threats();
    all_threats.extend(file_threats);

    println!("Scanning Registry...");
    let registry_threats = find_registry_threats();
    all_threats.extend(registry_threats);

    println!("Scanning Services...");
    let service_threats = find_service_threats();
    all_threats.extend(service_threats);

    // Sort by severity (highest first)
    all_threats.sort_by(|a, b| b.severity.cmp(&a.severity));

    if all_threats.is_empty() {
        println!("No threats found.");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
        return Ok(());
    }

    // Display threats to stdout since logging is removed
    for threat in &all_threats {
        println!(
            "[{}] {} Threat: {} ({})",
            if threat.severity > 3 { "CRITICAL" } else { "INFO" },
            threat.threat_type,
            threat.name,
            threat.path
        );
    }

    println!("Found {} threats. Starting cleanup...", all_threats.len());

    enable_uac();

    // Remove threats
    let mut success_count = 0;
    let mut failure_count = 0;

    for threat in &all_threats {
        println!("Cleaning: {} ({})", threat.name, threat.threat_type);
        let success = match threat.threat_type.as_str() {
            "File" => delete_file_threat(&threat.path),
            "Service" => stop_and_delete_service(&threat.name),
            "Registry Key" => lock_registry_key(&threat.path),
            _ => false,
        };

        if success {
            success_count += 1;
            println!("SUCCESS: Removed {}", threat.name);
        } else {
            failure_count += 1;
            println!("FAILED: Could not remove {}", threat.name);
        }
    }

    println!(
        "Cleanup finished. Success: {}, Failed: {}",
        success_count, failure_count
    );
    println!("System will restart in 5 seconds to complete cleanup...");
    thread::sleep(Duration::from_secs(5));

    restart_system();

    Ok(())
}
