# Complete Workflow Example

This guide walks through the entire process of encrypting and loading a PE file using LeCatchu.

## Prerequisites Checklist

- [ ] Python 3.7+ installed
- [ ] LeCatchu Python library available (lecatchu.py)
- [ ] GHC 9.4+ installed (via GHCup or Haskell Platform)
- [ ] Windows 10/11 x64 system
- [ ] Sample PE file to encrypt (e.g., calc.exe, notepad.exe)

## Step 1: Project Setup

Create a new directory and organize files:

```bash
mkdir pe-loader-project
cd pe-loader-project
```

Copy these files into the directory:
- `LeCatchu.hs` (Haskell crypto library)
- `Main.hs` (PE loader)
- `encoder.py` (Python encoder script)
- `lecatchu.py` (Python LeCatchu library)

## Step 2: Prepare Test Executable

For testing, we'll use Windows Calculator (safe and simple):

```powershell
# Copy calculator from System32
copy C:\Windows\System32\calc.exe .
```

Or use any other 64-bit Windows executable you want to test.

## Step 3: Encrypt the PE File

Run the encoder script:

```bash
python encoder.py calc.exe EncodedPayload.hs
```

Expected output:
```
[*] PE File Encoder with LeCatchu v9
[*] ===================================
[*] Input file: calc.exe
[*] Output module: EncodedPayload.hs
[*] Secret key: comp340659
[*] S-box seed: Lehncrypt
[*] Encryption params: xbase=1, interval=1
[*] IV params: length=256, xbase=1, interval=1

[*] Read 27648 bytes from input file
[*] Valid MZ signature detected
[*] Initializing LeCatchu engine...
[*] Encrypting PE file with LeCatchu...
[*] Encrypted payload size: 27904 bytes
[*] Size increase: 256 bytes (0.93%)
[*] Generating Haskell module: EncodedPayload.hs
[*] Haskell module generated successfully

[*] Next steps:
    1. Copy EncodedPayload.hs to your Haskell project directory
    2. Ensure LeCatchu.hs is in your project
    3. Build with: ghc -O2 Main.hs -o loader.exe
    4. Run: loader.exe

[*] Encoding complete!
```

Verify `EncodedPayload.hs` was created:
```bash
dir EncodedPayload.hs
```

## Step 4: Verify Configuration Match

**CRITICAL**: Ensure encoder and loader use identical parameters!

Check `encoder.py`:
```python
SECRET_KEY = "comp340659"
SBOX_SEED = "Lehncrypt"
XBASE = 1
INTERVAL = 1
IV_LENGTH = 256
IV_XBASE = 1
IV_INTERVAL = 1
```

Check `Main.hs`:
```haskell
secretKey = "comp340659"
leCatchuSboxSeed = "Lehncrypt"
leCatchuXBase = 1
leCatchuInterval = 1
leCatchuIVLength = 256
leCatchuIVXBase = 1
leCatchuIVInterval = 1
```

✅ If they match, proceed. ❌ If not, update and re-encrypt.

## Step 5: Install Haskell Dependencies

```bash
# Using Cabal
cabal update
cabal install --lib bytestring cryptonite memory containers random entropy

# Or using Stack (recommended for dependency management)
stack setup
stack build --only-dependencies
```

## Step 6: Build the Loader

### Option A: Using build script (Windows)
```bash
build.bat
```

### Option B: Manual GHC compilation
```bash
ghc -O2 -threaded Main.hs LeCatchu.hs EncodedPayload.hs -o loader.exe
```

### Option C: Using Cabal
```bash
cabal build
```

Expected output:
```
[1 of 3] Compiling EncodedPayload   ( EncodedPayload.hs, EncodedPayload.o )
[2 of 3] Compiling LeCatchu         ( LeCatchu.hs, LeCatchu.o )
[3 of 3] Compiling Main             ( Main.hs, Main.o )
Linking loader.exe ...
```

Verify the executable was created:
```bash
dir loader.exe
```

## Step 7: Test the Loader

Run the loader:

```bash
loader.exe
```

Expected output:
```
[*] PE Loader with LeCatchu v9 Decryption
[*] =======================================
[*] EncodedPayload module size: 27904 bytes
[*] Secret key: comp340659
[*] S-box seed: Lehncrypt
[*] Encryption params: xbase=1, interval=1
[*] IV params: length=256, xbase=1, interval=1
[*] Initializing LeCatchu decryption...
[*] Decrypted payload size: 27648 bytes
[*] Valid MZ signature detected after decryption
[*] PE data length: 27648
[*] DOS magic: 0x5a4d
[*] e_lfanew: 240
[*] NT signature: 0x4550
[*] Optional header magic: 0x20b
[*] SizeOfImage: 294912
[*] SizeOfHeaders: 1024
[*] Computed image size: 294912 bytes
[*] Allocated image base: 0x1c5a0e70000
[*] Number of sections: 4
[*] Copying section 0 size 26624
[*] Copying section 1 size 512
[*] Copying section 2 size 512
[*] Copying section 3 size 0
[*] Entry point RVA: 0x1234
[*] Entry point virtual address: 0x1c5a0e71234
[*] Subsystem: 2
[*] Execution gate passed. Executing entry point (in-memory).
```

At this point:
- Calculator should launch (if you encrypted calc.exe)
- Or your target program should execute

## Step 8: Verify Execution

Check if the program launched correctly:

```powershell
# List running processes
tasklist | findstr calc.exe
```

You should see the calculator process running.

## Troubleshooting Common Issues

### Issue 1: "Invalid MZ signature"

**Symptom**: After decryption, no MZ signature found

**Solution**:
1. Verify encryption parameters match exactly
2. Check that input file is a valid PE
3. Re-run encoder with correct parameters

```bash
# Re-encrypt with matching parameters
python encoder.py calc.exe EncodedPayload.hs
```

### Issue 2: "VirtualAlloc failed"

**Symptom**: Memory allocation error

**Solution**:
1. Close other applications to free memory
2. Use a smaller PE file for testing
3. Check available system memory

```powershell
# Check available memory
systeminfo | findstr "Available Physical Memory"
```

### Issue 3: "Failed to load DLL"

**Symptom**: Import resolution fails

**Solution**:
1. Ensure all required DLLs are in System32
2. Use Dependency Walker to check dependencies
3. Try a simpler executable (like notepad.exe)

```bash
# Test with notepad instead
python encoder.py C:\Windows\System32\notepad.exe EncodedPayload.hs
# Rebuild and run
build.bat
loader.exe
```

### Issue 4: Build errors

**Symptom**: GHC compilation fails

**Solution**:
1. Install missing dependencies
2. Check GHC version (9.4+ required)
3. Verify all source files are present

```bash
# Check GHC version
ghc --version

# Install dependencies
cabal install --lib bytestring cryptonite memory containers random entropy

# Clean and rebuild
del *.hi *.o
ghc -O2 Main.hs LeCatchu.hs EncodedPayload.hs -o loader.exe
```

## Advanced Testing

### Test 1: Multiple Executables

Encrypt different programs:

```bash
# Test with notepad
python encoder.py C:\Windows\System32\notepad.exe EncodedPayload.hs
build.bat
loader.exe

# Test with write.exe
python encoder.py C:\Windows\System32\write.exe EncodedPayload.hs
build.bat
loader.exe
```

### Test 2: Enhanced Encryption

Modify parameters for stronger encryption:

In `encoder.py` and `Main.hs`:
```python
XBASE = 3  # More hash iterations
IV_LENGTH = 512  # Larger IV
```

Re-encrypt and test:
```bash
python encoder.py calc.exe EncodedPayload.hs
build.bat
loader.exe
```

### Test 3: Performance Measurement

Time the encryption and loading:

```bash
# Time encryption
Measure-Command { python encoder.py calc.exe EncodedPayload.hs }

# Time loading (PowerShell)
Measure-Command { .\loader.exe }
```

## Clean Up

After testing, clean up intermediate files:

```bash
# Remove object files
del *.hi *.o

# Remove generated executable
del loader.exe

# Keep EncodedPayload.hs for next build
```

## Next Steps

Once the basic workflow is working:

1. **Experiment with parameters**: Try different xbase, interval values
2. **Test larger executables**: Encrypt 10MB+ programs
3. **Add error handling**: Improve error messages in loader
4. **Implement anti-debugging**: Add detection mechanisms
5. **Dynamic key generation**: Generate keys at runtime
6. **Network loading**: Load encrypted payloads from remote server

## Success Checklist

- [ ] Encoder runs without errors
- [ ] EncodedPayload.hs generated correctly
- [ ] Loader compiles successfully
- [ ] Decryption produces valid MZ signature
- [ ] PE loads into memory
- [ ] Entry point executes
- [ ] Target program launches/runs correctly

If all items are checked, congratulations! Your LeCatchu PE loader is working! 🎉

## Resources

- **LeCatchu Documentation**: See original Python library docs
- **PE Format**: Microsoft PE/COFF Specification
- **Haskell FFI**: https://wiki.haskell.org/Foreign_Function_Interface
- **GHC User Guide**: https://downloads.haskell.org/ghc/latest/docs/html/users_guide/

## Getting Help

If you encounter issues:
1. Check parameter synchronization (most common issue!)
2. Verify PE file validity with PE analysis tools
3. Test with simple executables first (calc.exe, notepad.exe)
4. Check system resources and permissions
5. Review GHC error messages carefully
