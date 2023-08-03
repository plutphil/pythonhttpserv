@echo off
pip install -r requirements.txt
mkdir output
cd output
pyinstaller --noconfirm --onefile --console  ../authserv.py
cd ..