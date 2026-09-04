@echo off
setlocal
chcp 65001 >nul
if "%~1"=="" (
  echo 用法：把抓包目录拖到本批处理文件上
  echo 或运行：导出录音.bat "抓包目录" [all^|answered^|unanswered]
  pause
  exit /b 2
)
set "STATUS=%~2"
if "%STATUS%"=="" set "STATUS=all"
py -3 "%~dp0pcapsip2wav.py" "%~1" -o "%~1\wav_output" --status "%STATUS%"
if errorlevel 1 pause
