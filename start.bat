@echo off
title ALDS - Anti-Leak Doc Sanitizer
python -m pip install -r requirements.txt
python doc_sanitizer.py
pause