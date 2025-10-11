"""
SecurePipe Library - Usage Examples and Test Cases
"""

from src.securepipe import SecurePipe  # Assuming your class is in secure_pipe.py
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


def example_2_with_expiration():
    """Example 2: Encryption with expiration time"""
    print("=== Example 2: With Expiration ===")
    tolerance = 2
    
    pipe = SecurePipe(secret_key="my-secret-key_12121212", uuid="a1b2c3d4-e5f6-7890-1234-567890abcdef", tolerance = tolerance) # Default value for tolerance is 30 seconds
    
    # Encrypt with 2 second expiration
    data = {"session": "xyz123"}
    expires_in = 2
    token = pipe.encrypt(data, expires_in= expires_in)
    
    # Immediate decryption works
    result = pipe.decrypt(token)
    print(f"Immediate decrypt: {result}")
    
    # Wait and try again
    sleep_in = expires_in + tolerance + 3
    print(f"Waiting {sleep_in} seconds...")
    time.sleep(sleep_in)
    result = pipe.decrypt(token)
    print(f"After expiration: {result}")
    print()


def example_3_dynamic_uuid():
    """Example 3: Dynamic UUID per token (no shared UUID)"""
    print("=== Example 3: Dynamic UUID ===")
    
    # Initialize WITHOUT a shared UUID
    pipe = SecurePipe(secret_key="my-secret-key_12121212")
    
    # Each token will have its own UUID embedded
    data = "sensitive information"
    token = pipe.encrypt(data)
    print(f"Token with embedded UUID: {token[:50]}...")
    
    # Decryption uses the embedded UUID
    decrypted = pipe.decrypt(token)
    print(f"Decrypted: {decrypted}")
    print()


def example_4_token_metadata():
    """Example 4: Reading token metadata without decryption"""
    print("=== Example 4: Token Metadata ===")
    
    pipe = SecurePipe(secret_key="my-secret_12121212", uuid="a1b2c3d4-e5f6-7890-1234-567890abcdef")
    
    token = pipe.encrypt({"data": "secret"}, expires_in=3600)
    
    # Get metadata without decrypting
    info = pipe.decode_token_info(token)
    print(f"Salt (hex): {info['salt'].hex()}")
    print(f"UUID: {info['uuid']}")
    print(f"Expires at: {info['expires_at']}")
    print()


def example_5_different_data_types():
    """Example 5: Encrypting different data types"""
    print("=== Example 5: Different Data Types ===")
    
    pipe = SecurePipe(secret_key="test-key_1212121212", uuid="a1b2c3d4-e5f6-7890-1234-567890abcdef")
    
    # Dictionary
    dict_data = {"name": "John", "age": 30}
    token1 = pipe.encrypt(dict_data)
    print(f"Dict: {pipe.decrypt(token1)}")
    
    # List
    list_data = [1, 2, 3, "four", 5.0]
    token2 = pipe.encrypt(list_data)
    print(f"List: {pipe.decrypt(token2)}")
    
    # String
    str_data = "Hello, World!"
    token3 = pipe.encrypt(str_data)
    print(f"String: {pipe.decrypt(token3)}")
    
    # Boolean
    bool_data = True
    tokenb = pipe.encrypt(bool_data)
    print(f"Bool: {pipe.decrypt(tokenb)}"
          "For Booleans they will return a string so handl that gracefully for True will return 'True' ")
    
    # Number
    num_data = 42
    token4 = pipe.encrypt(num_data)
    print(f"Number: {pipe.decrypt(token4)}"
          "for Numbers remeber to convert them back to intager coz it will be retured as string"
          "example: 'int(pipe.decrypt(token4))' ")
    print()


# ============================================================================
# ERROR SCENARIOS
# ============================================================================

def error_scenario_1_wrong_key():
    """Error: Decrypting with wrong secret key"""
    print("=== Error Scenario 1: Wrong Secret Key ===")
    
    pipe1 = SecurePipe(secret_key="correct-key_12121212", uuid="a1b2c3d4-e5f6-7890-1234-567890abcdef")
    token = pipe1.encrypt({"data": "secret"})
    
    pipe2 = SecurePipe(secret_key="wrong-key_1212121212", uuid="a1b2c3d4-e5f6-7890-1234-567890abcdef")
    result = pipe2.decrypt(token)
    print(f"Result: {result}")
    print()


def error_scenario_2_wrong_uuid():
    """Error: Decrypting with wrong UUID"""
    print("=== Error Scenario 2: Wrong UUID ===")
    
    pipe1 = SecurePipe(secret_key="key_121212121212121212", uuid="a1b2c3d4-e5f6-7890-1234-567890abcdef")
    token = pipe1.encrypt({"data": "secret"})
    
    pipe2 = SecurePipe(secret_key="key_121212121212121212", uuid="w2b2c334-6yf6-7890-1234-567890abcduo")
    result = pipe2.decrypt(token)
    print(f"Result: {result}")
    print()


def error_scenario_3_tampered_token():
    """Error: Tampered token"""
    print("=== Error Scenario 3: Tampered Token ===")
    
    pipe = SecurePipe(secret_key="key_12121212121212121212", uuid="a1b2c3d4-e5f6-7890-1234-567890abcdef")
    token = pipe.encrypt({"data": "secret"})
    
    # Tamper with token
    tampered = token[:-10] + "XXXXXXXXXX"
    result = pipe.decrypt(tampered)
    print(f"Result: {result}")
    print()

import uuid
def error_scenario_4_missing_uuid():
    """Error: Token with dynamic UUID decrypted without UUID context"""
    print("=== Error Scenario 4: Missing UUID Context ===")
    
    # Create token with dynamic UUID
    pipe1 = SecurePipe(secret_key="key_1212121212121212")  # No UUID
    token = pipe1.encrypt({"data": "secret"})
    
    # Try to decrypt with instance that expects shared UUID
    uuid_used = uuid.uuid4()
    pipe2 = SecurePipe(secret_key="key_1212121212121212", uuid=uuid_used)
    result = pipe2.decrypt(token)
    print(f"Result: {result}")
    print()
    
def error_scenario_5_wrong_uuid():
    """Error: Token diffrent UUID decrypted wrong UUID context"""
    print("=== Error Scenario 4: Wrong UUID Context ===")
    uuid_used = uuid.uuid4()
    # Create token with dynamic UUID
    pipe1 = SecurePipe(secret_key="key_1212121212121212_1111", uuid =uuid_used )  # No UUID
    token = pipe1.encrypt({"data": "secret"})
    
    # Try to decrypt with instance that expects shared UUID
    wrong_uuid = uuid.uuid4()
    pipe2 = SecurePipe(secret_key="key_1212121212121212_1111", uuid=wrong_uuid)
    result = pipe2.decrypt(token)
    print(
        f"UUID USED: {uuid_used}"
        f"UUID USED TO DECRYPT: {wrong_uuid}"
    )
    print(f"Result: {result}")
    print()


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == "__main__":
    # Run examples
    example_1_basic_encryption()
    example_2_with_expiration()
    example_3_dynamic_uuid()
    example_4_token_metadata()
    example_5_different_data_types()
    
    # Run error scenarios
    print("\n" + "="*60)
    print("ERROR SCENARIOS")
    print("="*60 + "\n")
    
    error_scenario_1_wrong_key()
    error_scenario_2_wrong_uuid()
    error_scenario_3_tampered_token()
    error_scenario_4_missing_uuid()
    error_scenario_5_wrong_uuid()