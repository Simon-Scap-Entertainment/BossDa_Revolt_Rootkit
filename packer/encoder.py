#!/usr/bin/env python3
"""
PE File Encoder using LeCatchu v9 - EXTERNAL PAYLOAD VERSION
Encrypts a PE file and saves as separate binary file (not embedded in source)

Usage:
    python encoder_external.py input.exe encrypted_payload.bin
"""

import sys
import os

# Import your LeCatchu library
from lecatchu import LeCatchu_Engine
from functools import partial

# Redirect print to stderr to avoid corrupting stdout when piping
print = partial(print, file=sys.stderr)

def encode_pe_file(input_path, output_path):
    """
    Encode a PE file using LeCatchu and output as binary file
    
    Args:
        input_path: Path to input PE file
        output_path: Path to output encrypted binary file
    """
    
    # Configuration - MUST MATCH the Haskell loader
    SECRET_KEY = "comp340659"
    SBOX_SEED = "Lehncrypt"
    XBASE = 1
    INTERVAL = 1
    IV_LENGTH = 256
    IV_XBASE = 1
    IV_INTERVAL = 1
    
    print("[*] PE File Encoder with LeCatchu v9 (External Payload)")
    print("[*] ======================================================")
    print(f"[*] Input file: {input_path}")
    print(f"[*] Output file: {output_path}")
    print(f"[*] Secret key: {SECRET_KEY}")
    print(f"[*] S-box seed: {SBOX_SEED}")
    print(f"[*] Encryption params: xbase={XBASE}, interval={INTERVAL}")
    print(f"[*] IV params: length={IV_LENGTH}, xbase={IV_XBASE}, interval={IV_INTERVAL}")
    print()
    
    # Read the PE file
    if not os.path.exists(input_path):
        print(f"[!] Error: Input file '{input_path}' not found")
        sys.exit(1)
    
    with open(input_path, 'rb') as f:
        pe_data = f.read()
    
    original_size = len(pe_data)
    print(f"[*] Read {original_size:,} bytes from input file")
    
    # Check if file is very large
    if original_size > 100 * 1024 * 1024:  # 100MB
        print(f"[*] WARNING: Large file detected ({original_size / (1024*1024):.2f} MB)")
        print(f"[*] Encryption may take a while...")
    
    # Verify it's a PE file
    if len(pe_data) < 2 or pe_data[:2] != b'MZ':
        print("[!] Warning: Input file doesn't start with MZ signature")
        print("[!] This may not be a valid PE file")
    else:
        print("[*] Valid MZ signature detected")
    
    # Initialize LeCatchu engine
    print("[*] Initializing LeCatchu engine...")
    engine = LeCatchu_Engine(
        sboxseed=SBOX_SEED,
        sboxseedxbase=XBASE,
        encoding_type="packet",
        encoding=False,
        shufflesbox=False,
        seperatorprov=True,
        unicodesupport=1114112,
        perlength=3
    )
    
    # Encrypt with IV
    print("[*] Encrypting PE file with LeCatchu...")
    print("[*] This may take a moment for large files...")
    
    encrypted = engine.encrypt_with_iv(
        pe_data,
        SECRET_KEY,
        xbase=XBASE,
        interval=INTERVAL,
        ivlength=IV_LENGTH,
        ivxbase=IV_XBASE,
        ivinterval=IV_INTERVAL
    )
    
    encrypted_size = len(encrypted)
    print(f"[*] Encrypted payload size: {encrypted_size:,} bytes")
    print(f"[*] Size increase: {encrypted_size - original_size:,} bytes ({((encrypted_size / original_size - 1) * 100):.2f}%)")
    
    # Write encrypted binary file
    if output_path == "-":
        sys.stdout.buffer.write(encrypted)
    else:
        print(f"[*] Writing encrypted payload to: {output_path}")
        with open(output_path, 'wb') as f:
            f.write(encrypted)
    
    print("[*] Encrypted payload saved successfully")
    print()
    print("[*] Next steps:")
    print(f"    1. Ensure {output_path} is in the same directory as loader.exe")
    print("    2. Build loader: ghc -O2 Main.hs LeCatchu.hs -o loader.exe")
    print("    3. Run: loader.exe")
    print()
    print("[*] Encoding complete!")


def main():
    if len(sys.argv) != 3:
        print("Usage: python encoder_external.py <input.exe> <output.bin>")
        print()
        print("Example:")
        print("  python encoder_external.py calc.exe encrypted_payload.bin")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    encode_pe_file(input_file, output_file)


if __name__ == "__main__":
    main()
