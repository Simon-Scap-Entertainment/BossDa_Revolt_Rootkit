import argparse
import sys
import os # Import os for os.SEEK_SET

# base64 and base32 are no longer needed
# from Crypto.Random import get_random_bytes # This is used for generating the final xor key, but that's removed

def encode(data, xor_key):
    print("Starting encoding process (without AES, base64, single XOR)...")



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
    b45_encoded = base45.b45encode(xored)
    
    print("Encoding complete!")
    return b45_encoded

def main():
    parser = argparse.ArgumentParser(description="Obfuscate a file with a complex pipeline.")
    parser.add_argument("input_file", help="The file to obfuscate.")
    parser.add_argument("output_file", help="The output binary file for the obfuscated payload.")
    parser.add_argument("--xor-key", default="comp340659", help="The XOR key to use for the main XOR step.")
    args = parser.parse_args()

    try:
        with open(args.input_file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found.")
        sys.exit(1)

    xor_key_bytes = args.xor_key.encode('utf-8')

    final_encoded_payload = encode(data, xor_key_bytes)

    if final_encoded_payload:
        with open(args.output_file, "wb") as f:
            f.write(final_encoded_payload)

        print(f"\n{args.output_file} has been generated with the new obfuscation data.")


if __name__ == "__main__":
    main()
