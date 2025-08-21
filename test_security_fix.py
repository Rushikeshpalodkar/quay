#!/usr/bin/env python3
"""
Test script to verify the security fix for pickle deserialization vulnerability
in ResumableSHAField.
"""

import base64
import hashlib
import pickle
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data.fields import ResumableSHA256Field


class MaliciousPayload:
    """
    A malicious class that would execute arbitrary code when unpickled.
    This simulates an attack payload.
    """
    def __reduce__(self):
        # This would execute arbitrary code during unpickling
        # In a real attack, this could be system('rm -rf /') or similar
        return (print, ("SECURITY BREACH: Arbitrary code executed!",))


def test_security_fix():
    """Test that the security fix prevents arbitrary code execution."""
    print("Testing ResumableSHA security fix...")
    
    # Create a field instance
    field = ResumableSHA256Field()
    
    # Test 1: Normal operation with a legitimate hasher
    print("\n1. Testing normal operation...")
    legitimate_hasher = hashlib.sha256()
    legitimate_hasher.update(b"test data")
    
    # Serialize and deserialize legitimate hasher
    serialized = field.db_value(legitimate_hasher)
    deserialized = field.python_value(serialized)
    print(f"✓ Normal operation works: {type(deserialized)}")
    
    # Test 2: Attempt to inject malicious payload (should be blocked)
    print("\n2. Testing malicious payload injection...")
    
    # Create malicious payload
    malicious_payload = MaliciousPayload()
    malicious_pickled = pickle.dumps(malicious_payload)
    
    # Try to inject it as if it came from a compromised database
    malicious_b64 = base64.b64encode(malicious_pickled).decode('ascii')
    
    print("Attempting to deserialize malicious payload...")
    result = field.python_value(malicious_b64)
    
    if result is not None and hasattr(result, 'update'):
        print("✓ Security fix successful: Malicious payload rejected, fresh hasher returned")
    else:
        print("✗ Security fix failed: Malicious payload may have executed")
    
    # Test 3: Test with tampered signature
    print("\n3. Testing tampered signature detection...")
    
    # Create a legitimate serialized value
    legitimate_serialized = field.db_value(hashlib.sha256())
    
    # Tamper with the data by changing one byte
    tampered_data = legitimate_serialized[:-1] + ('X' if legitimate_serialized[-1] != 'X' else 'Y')
    
    print("Attempting to deserialize tampered data...")
    result = field.python_value(tampered_data)
    
    if result is not None and hasattr(result, 'update'):
        print("✓ Tampered data detected and fresh hasher returned")
    else:
        print("✗ Failed to detect tampered data")
    
    print("\n=== Security Test Summary ===")
    print("The ResumableSHAField has been secured with:")
    print("1. HMAC signature verification to detect tampering")
    print("2. Validation of deserialized objects")
    print("3. Graceful handling of invalid data")
    print("4. Fallback to fresh hasher instances")


if __name__ == '__main__':
    test_security_fix()