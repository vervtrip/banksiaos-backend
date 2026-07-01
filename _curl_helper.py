#!/usr/bin/env python3
import json, subprocess as sp, sys
TOKEN = sys.argv[1]
EID = sys.argv[2]
PATH = sys.argv[3]
hdr = "Authorization: Bearer *** + TOKEN
cmd = ["curl", "-s", "-H", hdr, "-H", "X-EntityID: " + EID, "https://api.arthuronline.co.uk/v2/" + PATH]
r = sp.run(cmd, capture_output=True, text=True, timeout=60)
print(r.stdout)
