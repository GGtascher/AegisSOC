@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" python -m venv .venv
call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
pushd frontend
call npm install
call npm run build
popd
pyinstaller --noconfirm --clean --onefile --name AegisSOC ^
  --add-data "frontend\dist;frontend\dist" ^
  --add-data "rules;rules" ^
  --hidden-import win32evtlog main.py
if errorlevel 1 (
  echo Source build completed, but the optional EXE build failed.
  exit /b 1
)
echo Build completed. Run run.bat or dist\AegisSOC.exe.
endlocal
