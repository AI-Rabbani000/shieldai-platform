#!/usr/bin/env python3
"""Fix tool_defs to handle callable tool specs (functions, not dicts)."""
import os

f = "/opt/gds-os/apps/api/gds_api/reasoning/kernel_agent_runner.py"
lines = open(f).readlines()

new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    # Find the tool_defs loop
    if 'for tool_name, tool_spec in TOOL_REGISTRY.items():' in line and i + 5 < len(lines):
        indent = line[:len(line) - len(line.lstrip())]
        new_lines.append(line)
        new_lines.append(indent + '    if callable(tool_spec):\n')
        new_lines.append(indent + '        desc = tool_spec.__doc__ or "Execute %s" %% tool_name\n')
        new_lines.append(indent + '        params = {"type": "object", "properties": {}}\n')
        new_lines.append(indent + '    else:\n')
        new_lines.append(indent + '        desc = tool_spec.get("description", "Execute %s" %% tool_name) if hasattr(tool_spec, "get") else str(tool_spec)\n')
        new_lines.append(indent + '        params = tool_spec.get("parameters", {"type": "object", "properties": {}}) if hasattr(tool_spec, "get") else {"type": "object", "properties": {}}\n')
        # Skip the old lines that had tool_spec.get
        i += 1
        # Skip until we find the closing of the append
        while i < len(lines) and 'tool_defs.append' not in lines[i]:
            i += 1
        # Now add the append with desc/params
        new_lines.append(indent + '    tool_defs.append({\n')
        new_lines.append(indent + '        "type": "function",\n')
        new_lines.append(indent + '        "function": {\n')
        new_lines.append(indent + '            "name": tool_name,\n')
        new_lines.append(indent + '            "description": desc,\n')
        new_lines.append(indent + '            "parameters": params\n')
        new_lines.append(indent + '        }\n')
        new_lines.append(indent + '    })\n')
        # Skip old append lines
        i += 1
        while i < len(lines) and '})' not in lines[i-1]:
            if '})' in lines[i]:
                i += 1
                break
            i += 1
        continue
    new_lines.append(line)
    i += 1

open(f, 'w').write(''.join(new_lines))

# Verify compiles
try:
    compile(open(f).read(), f, 'exec')
    print("Compiles OK")
except SyntaxError as e:
    print("SYNTAX ERROR: %s at line %d" % (e.msg, e.lineno))

# Verify import
import sys
sys.path.insert(0, "/opt/gds-os/apps/api")
for mod in list(sys.modules.keys()):
    if "gds_api" in mod:
        del sys.modules[mod]
try:
    from gds_api.reasoning.kernel_agent_runner import run_kernel_agent_runner
    print("Import OK")
except Exception as e:
    print("Import FAILED: %s" % e)
