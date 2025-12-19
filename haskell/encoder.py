import argparse
import sys
import os # Import os for os.SEEK_SET

# base64 and base32 are no longer needed
# from Crypto.Random import get_random_bytes # This is used for generating the final xor key, but that's removed

def encode(data, xor_key):
    print("Starting encoding process (without AES, base64, single XOR)...")

    # base16 (hex) - Apply to original data directly

    # xor
    print("Step 1/2: XORing (main key)...")
    xored = bytes([b ^ xor_key[i % len(xor_key)] for i, b in enumerate(data)])

    # base32

    # base45
    print("Step 2/2: Base45 encoding...")
    try:
        import base45
    except ImportError:
        print("base45 library not found. Please install it using: pip install base45")
        return None
    b45_encoded = base45.b45encode(b32_encoded)
    
    print("Encoding complete!")
    return b45_encoded # Final base16 of the whole thing

def main():
    parser = argparse.ArgumentParser(description="Obfuscate a file with a complex pipeline.")
    parser.add_argument("input_file", help="The file to obfuscate.")
    parser.add_argument("--xor-key", default="comp340659", help="The XOR key to use for the main XOR step.")
    args = parser.parse_args()

    try:
        with open(args.input_file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found.")
        sys.exit(1)

    xor_key_bytes = args.xor_key.encode('utf-8')

    final_base16_encoded_payload = encode(data, xor_key_bytes)

    if final_base16_encoded_payload:
        with open("EncodedPayload.hs", "w") as f:
            f.write("-- Auto-generated encoded payload\n")
            f.write("module EncodedPayload (encodedPayload) where\n\n")
            f.write("import qualified Data.ByteString as BS\n\n")
            f.write("encodedPayload :: BS.ByteString\n")
            f.write("encodedPayload = BS.pack [\n")
            
            chunk_size_hs = 32
            for i in range(0, len(final_base16_encoded_payload), chunk_size_hs):
                chunk = final_base16_encoded_payload[i:i+chunk_size_hs]
                f.write("    " + ", ".join([f"0x{b:02x}" for b in chunk]) + ",\n")
            # Remove trailing comma from the last element if it exists
            if f.tell() > 0 and final_base16_encoded_payload: # Check if file is not empty and payload is not empty
                f.seek(f.tell() - 2, os.SEEK_SET) # Move cursor back by 2 to overwrite ",\n"
                f.truncate() # Truncate from current position
                f.write("\n  ]\n")
            else:
                f.write("\n  ]\n")

        print("\nEncodedPayload.hs has been generated with the new obfuscation data.")


if __name__ == "__main__":
    main()
