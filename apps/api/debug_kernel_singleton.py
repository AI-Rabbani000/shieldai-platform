#!/usr/bin/env python3
"""
Debug: Check if get_kernel() returns the same instance across requests
"""
import sys
sys.path.insert(0, "/opt/gds-os/apps/api")

# Check the get_kernel function
f = "/opt/gds-os/apps/api/gds_kernel/kernel_router.py"
content = open(f).read()

# Find the get_kernel function
import re
match = re.search(r'def get_kernel\(\).*?(?=\ndef |\nclass |\Z)', content, re.DOTALL)
if match:
    print("=== get_kernel() function ===")
    print(match.group(0))
else:
    print("get_kernel not found!")

# Check if _kernel is a global
if "_kernel" in content:
    print("\n_kernel global: FOUND")
    # Find where _kernel is initialized
    for i, line in enumerate(content.split("\n")):
        if "_kernel" in line and "global" not in line:
            print(f"  Line {i+1}: {line.strip()}")
else:
    print("\n_kernel global: NOT FOUND — this is the bug!")
    print("The get_kernel() function needs a module-level _kernel = None variable")

# Check if the router has any startup events
if "startup" in content.lower() or "lifespan" in content.lower():
    print("\nStartup/lifespan event: FOUND")
else:
    print("\nStartup/lifespan event: NOT FOUND")

# Check if there's an app.state reference
if "app.state" in content:
    print("app.state: FOUND")
else:
    print("app.state: NOT FOUND")
