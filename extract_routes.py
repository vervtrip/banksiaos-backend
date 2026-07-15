#!/usr/bin/env python3
"""Extract all Flask routes from banksia_os.py and app.py for the migration inventory."""
import re, json

def extract_routes(path, prefix=""):
    with open(path) as f:
        lines = f.readlines()
    routes = []
    for i, line in enumerate(lines):
        # Match @bp.route("/path", methods=["GET","POST"])
        m = re.match(
            r'@(\w+)\.(?:route|get|post|put|patch|delete)\([\'"]([^\'"]+)[\'"]',
            line
        )
        if not m:
            continue
        bp = m.group(1)
        route_path = prefix + m.group(2)
        # Default method
        methods = ["GET"]

        # Check if methods= is explicitly set
        rest = line[m.end():]
        meth_m = re.search(r'methods\s*=\s*\[([^\]]*)\]', rest)
        if meth_m:
            methods = [x.strip().strip("'\"").upper() for x in meth_m.group(1).split(",")]
        elif "route(" in line and "methods=" not in rest:
            pass  # GET is correct default

        # Get function name
        func = "?"
        for j in range(i+1, min(i+5, len(lines))):
            fm = re.match(r'def (\w+)\(', lines[j])
            if fm:
                func = fm.group(1)
                break
        routes.append({
            "bp": bp,
            "path": route_path,
            "methods": methods,
            "function": func
        })
    return routes

all_routes = []
all_routes.extend(extract_routes("banksia_os.py", "/api/banksia-os"))
# Also get auth routes from app.py
all_routes.extend(extract_routes("app.py"))

print(json.dumps(all_routes, indent=2))
print(f"\nTotal routes: {len(all_routes)}")
