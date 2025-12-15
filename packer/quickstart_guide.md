# Quick Start Guide

Get up and running with LeCatchu PE Loader in 5 minutes!

## 🚀 One-Command Build (Recommended)

### Windows
```batch
build.bat
```

### Linux/macOS/WSL
```bash
chmod +x build.sh
./build.sh
```

The script will:
1. ✅ Check all prerequisites (Python, GHC, required files)
2. 🎯 Ask which PE file to encode
3. 🔒 Encrypt the file with LeCatchu
4. 🔨 Build the loader
5. ▶️ Offer to run immediately

## 📋 Interactive Prompts

### Prompt 1: Select PE File

```
Enter the path to the PE file you want to encode:
Examples:
  - C:\Windows\System32\calc.exe
  - C:\Windows\System32\notepad.exe
  - .\myprogram.exe

PE file path: _
```

**What to enter:**
- Absolute path: `C:\Windows\System32\calc.exe`
- Relative path: `.\myprogram.exe`
- Drag and drop the file into the terminal (works on most terminals)

### Prompt 2: Confirm File

```
[*] Target file: calc.exe
[*] File size: 27648 bytes

Is this the correct file? (Y/N)
Confirm: _
```

Type `Y` and press Enter to continue.

### Prompt 3: Run Loader

```
Would you like to run the loader now? (Y/N)
Run loader: _
```

- Type `Y` to run immediately
- Type `N` to exit (you can run `loader.exe` manually later)

## 🎯 Alternative: Command-Line Argument

Skip the file selection prompt by providing the file as an argument:

### Windows
```batch
build.bat C:\Windows\System32\calc.exe
```

### Linux/macOS/WSL
```bash
./build.sh /mnt/c/Windows/System32/calc.exe
```

The script will still ask for confirmation before proceeding.

## 📝 Example Session

Here's what a complete session looks like:

```
C:\project> build.bat

[*] LeCatchu PE Loader - Complete Build Script
[*] ============================================

[*] Step 1: Checking prerequisites...

[*] Python version:
Python 3.11.5

[*] GHC version:
The Glorious Glasgow Haskell Compilation System, version 9.4.7

[*] All prerequisites satisfied

[*] Step 2: Select PE file to encode

Enter the path to the PE file you want to encode:
Examples:
  - C:\Windows\System32\calc.exe
  - C:\Windows\System32\notepad.exe
  - .\myprogram.exe

PE file path: C:\Windows\System32\calc.exe
[*] Target file: calc.exe
[*] File size: 27648 bytes

Is this the correct file? (Y/N)
Confirm: Y

[*] Step 3: Encoding PE file with LeCatchu...

[*] PE File Encoder with LeCatchu v9
[*] ===================================
[*] Read 27648 bytes from input file
[*] Valid MZ signature detected
[*] Initializing LeCatchu engine...
[*] Encrypting PE file with LeCatchu...
[*] Encrypted payload size: 27904 bytes
[*] Haskell module generated successfully

[*] Encoding successful!
[*] EncodedPayload.hs size: 450123 bytes

[*] Step 4: Building loader.exe...

[1 of 3] Compiling EncodedPayload
[2 of 3] Compiling LeCatchu
[3 of 3] Compiling Main
Linking loader.exe ...

[*] Build successful!
[*] Loader size: 12845056 bytes

[*] ============================================
[*] BUILD COMPLETE
[*] ============================================

[*] Summary:
[*]   Target PE: C:\Windows\System32\calc.exe
[*]   Original size: 27648 bytes
[*]   Encoded module: 450123 bytes
[*]   Loader size: 12845056 bytes

Would you like to run the loader now? (Y/N)
Run loader: Y

[*] ============================================
[*] RUNNING LOADER
[*] ============================================

[*] PE Loader with LeCatchu v9 Decryption
[*] Valid MZ signature detected after decryption
[*] Entry point executed successfully

[*] Loader execution finished
```

## 🧪 Testing with Different Executables

### Test 1: Windows Calculator (Simple)
```batch
build.bat C:\Windows\System32\calc.exe
```
**Expected**: Calculator launches

### Test 2: Notepad (Medium)
```batch
build.bat C:\Windows\System32\notepad.exe
```
**Expected**: Notepad launches

### Test 3: WordPad (Larger)
```batch
build.bat C:\Windows\System32\write.exe
```
**Expected**: WordPad launches

### Test 4: Custom Executable
```batch
build.bat C:\path\to\your\program.exe
```
**Expected**: Your program launches

## ⚠️ Common Issues

### Issue: "Python not found"
**Solution**: Install Python 3.7+ from https://www.python.org/
- Make sure to check "Add Python to PATH" during installation

### Issue: "GHC not found"
**Solution**: Install GHC via GHCup
```bash
# Windows (PowerShell)
Set-ExecutionPolicy Bypass -Scope Process -Force;[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; try { Invoke-Command -ScriptBlock ([ScriptBlock]::Create((Invoke-WebRequest https://www.haskell.org/ghcup/sh/bootstrap-haskell.ps1 -UseBasicParsing))) -ArgumentList $true } catch { Write-Error $_ }

# Linux/macOS
curl --proto '=https' --tlsv1.2 -sSf https://get-ghcup.haskell.org | sh
```

### Issue: "lecatchu.py not found"
**Solution**: Download or copy the LeCatchu Python library to your project directory

### Issue: "File not found"
**Solution**: 
- Check the path is correct
- Use absolute paths for system files
- Try dragging the file into the terminal

### Issue: "Invalid MZ signature after decryption"
**Solution**: This means encryption parameters don't match
- Don't modify `Main.hs` encryption parameters
- Re-run `build.bat` with a clean copy of files

## 🎓 What Happens Under the Hood

```
┌─────────────────────────────────────────────┐
│ 1. Prerequisites Check                      │
│    - Python 3.7+                            │
│    - GHC 9.4+                               │
│    - Required files                         │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ 2. File Selection                           │
│    - User provides PE file path             │
│    - Validates file exists                  │
│    - Shows file info                        │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ 3. Encoding (encoder.py)                    │
│    - Read PE file                           │
│    - Initialize LeCatchu engine             │
│    - Encrypt with IV                        │
│    - Generate EncodedPayload.hs             │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ 4. Compilation (GHC)                        │
│    - Compile LeCatchu.hs                    │
│    - Compile EncodedPayload.hs              │
│    - Compile Main.hs                        │
│    - Link into loader.exe                   │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│ 5. Execution (Optional)                     │
│    - Decrypt payload with LeCatchu          │
│    - Load PE into memory                    │
│    - Resolve imports/relocations            │
│    - Execute entry point                    │
└─────────────────────────────────────────────┘
```

## 📦 Files Generated

After running the build script, you'll have:

```
project/
├── EncodedPayload.hs    [Generated] - Encrypted PE as Haskell module
├── loader.exe           [Generated] - Final executable
├── LeCatchu.hs          [Required] - Crypto library
├── Main.hs              [Required] - PE loader code
├── encoder.py           [Required] - Encryption script
├── lecatchu.py          [Required] - Python LeCatchu library
└── build.bat / build.sh [Required] - This build script
```

## 🔄 Workflow Summary

1. **First time**: `build.bat` → Select file → Builds everything
2. **Change target**: `build.bat` → Select new file → Rebuilds
3. **Just run**: `loader.exe` → Runs last built loader
4. **Different file**: `build.bat newfile.exe` → Quick rebuild

## 🎯 Pro Tips

1. **Faster builds**: Keep a terminal open in your project directory
2. **Test suite**: Create a batch file that tests multiple executables
3. **Custom keys**: Edit encryption parameters in both `encoder.py` and `Main.hs`
4. **Debug mode**: Add `-debug` flag to GHC options for debugging info
5. **Size optimization**: Use `-O2` for smaller binaries (already default)

## 📚 Next Steps

Once you're comfortable with the basics:
- Read `EXAMPLE_WORKFLOW.md` for detailed troubleshooting
- See `README_PE_Loader.md` for security considerations
- Experiment with different encryption parameters
- Try larger executables (games, applications)

## ✅ Success Checklist

After running `build.bat` or `build.sh`:

- [ ] No error messages during prerequisite check
- [ ] File selection accepted
- [ ] Encoding completed successfully
- [ ] Compilation finished without errors
- [ ] loader.exe created
- [ ] (Optional) Loader executed successfully
- [ ] Target program launched

If all items checked, you're ready to go! 🎉

## 🆘 Need Help?

1. Check prerequisites: Python 3.7+, GHC 9.4+
2. Verify all required files are present
3. Test with simple executable (calc.exe) first
4. Review error messages carefully
5. Consult `EXAMPLE_WORKFLOW.md` for detailed troubleshooting

---

**Ready to start?** Just run `build.bat` (Windows) or `./build.sh` (Linux/Mac) and follow the prompts!
