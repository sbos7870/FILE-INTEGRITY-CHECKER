import hashlib
import os

def calculate_hash(filepath, algorithm="sha256"):
    """Calculates the hash of a given file using the specified algorithm."""
    try:
        hasher = hashlib.new(algorithm)
        with open(filepath, 'rb') as file:
            while True:
                chunk = file.read(4096)  # Read in chunks to handle large files
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None
    except ValueError:
        print(f"Error: Unsupported hashing algorithm: {algorithm}")
        return None

def record_hash(filepath, hash_value_file="file_hashes.txt"):
    """Records the hash value of a file in a designated file."""
    with open(hash_value_file, 'a') as f:
        f.write(f"{filepath}:{hash_value}\n")
    print(f"Hash for '{filepath}' recorded.")

def verify_hash(filepath, hash_value_file="file_hashes.txt"):
    """Verifies the current hash of a file against a recorded hash."""
    current_hash = calculate_hash(filepath)
    if current_hash is None:
        return

    recorded_hash = None
    try:
        with open(hash_value_file, 'r') as f:
            for line in f:
                stored_filepath, stored_hash = line.strip().split(':')
                if stored_filepath == filepath:
                    recorded_hash = stored_hash
                    break
    except FileNotFoundError:
        print(f"Warning: Hash record file '{hash_value_file}' not found. Cannot verify.")
        return

    if recorded_hash:
        if current_hash == recorded_hash:
            print(f"Integrity check passed for '{filepath}'. Hashes match.")
        else:
            print(f"Integrity check failed for '{filepath}'. Hashes do not match.")
            print(f"  Current Hash: {current_hash}")
            print(f"  Recorded Hash: {recorded_hash}")
    else:
        print(f"No recorded hash found for '{filepath}'.")

def main():
    while True:
        print("\nFile Integrity Checker Menu:")
        print("1. Calculate and Record Hash")
        print("2. Verify Hash")
        print("3. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            filepath = input("Enter the path to the file: ")
            algorithm = input("Enter the hashing algorithm (e.g., sha256, md5): ").lower()
            hash_value = calculate_hash(filepath, algorithm)
            if hash_value:
                record_hash(filepath, hash_value)
        elif choice == '2':
            filepath = input("Enter the path to the file to verify: ")
            verify_hash(filepath)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
