@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================
echo  DTrack Windows 打包脚本
echo ============================================
echo.

echo [1/3] 构建前端 (Vue3 -^> dtrack/static) ...
pushd web
if not exist node_modules (
    echo   安装前端依赖中...
    call npm install || (echo   [X] npm install 失败 & popd & pause & exit /b 1)
)
call npm run build || (echo   [X] npm run build 失败 & popd & pause & exit /b 1)
popd

echo.
echo [2/3] 检查 PyInstaller ...
python -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo   安装 PyInstaller 中...
    python -m pip install pyinstaller || (echo   [X] 安装 PyInstaller 失败 & pause & exit /b 1)
)

echo.
echo [3/3] PyInstaller 打包 (单文件 exe) ...
python -m PyInstaller --noconfirm --clean packaging\dtrack.spec || (echo   [X] 打包失败 & pause & exit /b 1)

echo.
echo ============================================
echo  完成！可执行程序: dist\DTrack.exe
echo  双击运行即可启动 Web 管理平台 (http://127.0.0.1:8080)
echo  数据库/配置默认在运行目录的 db\config 下自动创建
echo ============================================
pause
