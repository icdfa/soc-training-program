#!/usr/bin/env python3
"""
Hash Calculator Script
Calculates MD5, SHA1, SHA256, and SHA512 hashes for files

Usage: python3 hash_calculator.py <file_path>
"""

import sys
import hashlib
import os


def calculate_hashes(file_path):
    """
    Calculate multiple hash types for a given file
    
    Args:
        file_path (str): Path to the file to hash
        
    Returns:
        dict: Dictionary containing hash types and their values
    """
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found!")
        return None
    
    # Initialize hash objects
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    sha512_hash = hashlib.sha512()
    
    # Read file in chunks to handle large files
    try:
        with open(file_path, 'rb') as f:
            # Read file in 64KB chunks
            for chunk in iter(lambda: f.read(65536), b''):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                sha512_hash.update(chunk)
    except Exception as e:
        print(f"Error reading file: {e}")
        return None
    
    # Return hash values
    return {
        'MD5': md5_hash.hexdigest(),
        'SHA1': sha1_hash.hexdigest(),
        'SHA256': sha256_hash.hexdigest(),
        'SHA512': sha512_hash.hexdigest()
    }


def get_file_info(file_path):
    """
    Get basic file information
    
    Args:
        file_path (str): Path to the file
        
    Returns:
        dict: Dictionary containing file information
    """
    stat_info = os.stat(file_path)
    return {
        'Filename': os.path.basename(file_path),
        'Path': os.path.abspath(file_path),
        'Size': f"{stat_info.st_size:,} bytes",
        'Size (KB)': f"{stat_info.st_size / 1024:.2f} KB",
        'Size (MB)': f"{stat_info.st_size / (1024 * 1024):.2f} MB"
    }


def print_results(file_path, hashes, file_info):
    """
    Print the results in a formatted manner
    
    Args:
        file_path (str): Path to the file
        hashes (dict): Dictionary of hash values
        file_info (dict): Dictionary of file information
    """
    print("\n" + "="*70)
    print("FILE HASH CALCULATOR")
    print("="*70)
    
    print("\nFILE INFORMATION:")
    print("-"*70)
    for key, value in file_info.items():
        print(f"{key:15s}: {value}")
    
    print("\nHASH VALUES:")
    print("-"*70)
    for hash_type, hash_value in hashes.items():
        print(f"{hash_type:15s}: {hash_value}")
    
    print("\nVIRUSTOTAL LOOKUP:")
    print("-"*70)
    print(f"https://www.virustotal.com/gui/file/{hashes['SHA256']}")
    
    print("\nHYBRID ANALYSIS LOOKUP:")
    print("-"*70)
    print(f"https://www.hybrid-analysis.com/search?query={hashes['SHA256']}")
    
    print("\n" + "="*70)


def main():
    """
    Main function
    """
    if len(sys.argv) != 2:
        print("Usage: python3 hash_calculator.py <file_path>")
        print("\nExample:")
        print("  python3 hash_calculator.py malware.exe")
        print("  python3 hash_calculator.py /path/to/suspicious/file.dll")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Get file information
    file_info = get_file_info(file_path)
    
    # Calculate hashes
    print(f"\nCalculating hashes for: {file_path}")
    print("Please wait...")
    
    hashes = calculate_hashes(file_path)
    
    if hashes:
        print_results(file_path, hashes, file_info)
        
        # Ask if user wants to save results
        save = input("\nSave results to file? (y/n): ").strip().lower()
        if save == 'y':
            output_file = f"{os.path.basename(file_path)}_hashes.txt"
            with open(output_file, 'w') as f:
                f.write("="*70 + "\n")
                f.write("FILE HASH CALCULATOR RESULTS\n")
                f.write("="*70 + "\n\n")
                f.write("FILE INFORMATION:\n")
                f.write("-"*70 + "\n")
                for key, value in file_info.items():
                    f.write(f"{key:15s}: {value}\n")
                f.write("\nHASH VALUES:\n")
                f.write("-"*70 + "\n")
                for hash_type, hash_value in hashes.items():
                    f.write(f"{hash_type:15s}: {hash_value}\n")
                f.write("\nVIRUSTOTAL LOOKUP:\n")
                f.write("-"*70 + "\n")
                f.write(f"https://www.virustotal.com/gui/file/{hashes['SHA256']}\n")
                f.write("\nHYBRID ANALYSIS LOOKUP:\n")
                f.write("-"*70 + "\n")
                f.write(f"https://www.hybrid-analysis.com/search?query={hashes['SHA256']}\n")
            print(f"\nResults saved to: {output_file}")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
