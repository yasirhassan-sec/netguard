import os
import sys
import tempfile

# Isolated data dir so tests never touch the real database. Must be set before importing scanner.
os.environ["NETGUARD_HOME"] = tempfile.mkdtemp(prefix="netguard-test-")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
