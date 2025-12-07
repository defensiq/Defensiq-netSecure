@echo off
REM Build script for Defensiq Network Security
REM Requires PyInstaller: pip install pyinstaller

echo ====================================
echo Building Defensiq Network Security
echo ====================================
echo.

REM Check if PyInstaller is installed
python -c "import PyInstaller" 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] PyInstaller is not installed!
    echo Please install it with: pip install pyinstaller
    pause
    exit /b 1
)

echo [1/3] Cleaning previous builds...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
echo Done.
echo.

echo [2/3] Building executable with PyInstaller...
pyinstaller defensiq.spec --clean
if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)
echo Done.
echo.

echo [3/3] Creating release package...
if not exist "dist\Defensiq-Release" mkdir "dist\Defensiq-Release"
xcopy /E /I /Y "dist\Defensiq\*" "dist\Defensiq-Release\"
copy /Y "README.md" "dist\Defensiq-Release\"
copy /Y "LICENSE" "dist\Defensiq-Release\" 2>nul
echo Done.
echo.

echo ====================================
echo Build completed successfully!
echo ====================================
echo.
echo Executable location: dist\Defensiq-Release\Defensiq.exe
echo.
echo IMPORTANT: 
echo - Run as Administrator
echo - PyDivert driver required (see README.md)
echo.
pause
