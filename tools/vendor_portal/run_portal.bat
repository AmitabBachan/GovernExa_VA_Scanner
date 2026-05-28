@echo off
echo Starting GovernExa Vendor License Portal...
echo You must have 'fastapi' and 'uvicorn' installed via pip.
echo Portal will be available at: http://localhost:8001

python -m uvicorn main:app --port 8001 --reload
