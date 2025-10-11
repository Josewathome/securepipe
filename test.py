from securepipe import SecurePipe
import time

# ============================================================================
# BASIC USAGE EXAMPLES
# ============================================================================

def example_1_basic_encryption():
    """Example 1: Basic encryption/decryption with shared UUID"""
    print("=== Example 1: Basic Usage ===")
    
    # Initialize with a secret key and shared UUID
    pipe = SecurePipe(
        secret_key="my-super-secret-key-12345232323",
        uuid="a1b2c3d4-e5f6-7890-1234-567890abcdef"
    )
    
    # Encrypt some data
    data = {"user_id": 123, "role": "admin", "permissions": ["read", "write"]}
    token = pipe.encrypt(data)
    print(f"Encrypted token: {token[:50]}...")
    
    # Decrypt the data
    decrypted = pipe.decrypt(token)
    print(f"Decrypted data: {decrypted}")
    print()
    
if __name__ == "__main__":
    # Run examples
    example_1_basic_encryption()