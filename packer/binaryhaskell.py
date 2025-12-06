#!/usr/bin/env python3
import sys

def xor_encode(data, key):
    key_bytes = key.encode('utf-8')
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

def bytes_to_haskell_hex(data, var_name="encodedPayload"):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ', '.join(f'0x{b:02x}' for b in chunk)
        lines.append(f"    {hex_str}")
    
    hex_content = ',\n'.join(lines)
    
    # MODULE olarak export et - main YOK!
    haskell_code = f"""-- Auto-generated encoded payload
-- Total size: {len(data)} bytes

module EncodedPayload (encodedPayload) where

import qualified Data.ByteString as BS
import Data.Word

{var_name} :: BS.ByteString
{var_name} = BS.pack
  [ {hex_content}
  ]
"""
    return haskell_code

def main():
    if len(sys.argv) != 4:
        print("Usage: python encoder.py <input.exe> <output.hs> <secret_key>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    secret_key = sys.argv[3]
    
    with open(input_file, 'rb') as f:
        pe_data = f.read()
    
    print(f"[+] Read {len(pe_data)} bytes from {input_file}")
    
    encoded_data = xor_encode(pe_data, secret_key)
    print(f"[+] Encoded with key: {secret_key}")
    
    haskell_code = bytes_to_haskell_hex(encoded_data, "encodedPayload")
    
    with open(output_file, 'w') as f:
        f.write(haskell_code)
    
    print(f"[+] Written Haskell module to {output_file}")

if __name__ == "__main__":
    main()
