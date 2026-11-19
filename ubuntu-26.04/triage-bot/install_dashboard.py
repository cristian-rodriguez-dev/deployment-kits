#!/usr/bin/env python3
"""Add a read-only dashboard route without replacing the existing bot logic."""
from pathlib import Path
import sys

main = Path('app/main.py')
page = Path('app/dashboard.html')
if not main.is_file() or not page.is_file():
    sys.exit('ERROR: run from security-triage-bot directory; app/main.py and app/dashboard.html required')
src = main.read_text(encoding='utf-8')
if "@app.get('/dashboard'" in src or '@app.get("/dashboard"' in src:
    print('Dashboard endpoint already present; no change')
else:
    if 'app = FastAPI(' not in src:
        sys.exit('ERROR: FastAPI app not found; no changes')
    addition = '''\n\n# Read-only incident dashboard. The page does not include secrets.\n# Data access remains protected by the existing /incidents Bearer token.\n@app.get('/dashboard', include_in_schema=False)\ndef incident_dashboard():\n    from fastapi.responses import FileResponse\n    return FileResponse(Path(__file__).with_name('dashboard.html'), media_type='text/html',\n                        headers={'Cache-Control': 'no-store',\n                                 'X-Content-Type-Options': 'nosniff',\n                                 'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"})\n'''
    main.write_text(src.rstrip()+'\n'+addition, encoding='utf-8')
    print('Dashboard endpoint appended; existing functions preserved')
