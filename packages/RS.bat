@echo off
taskkill /f /im explorer.exe
del /a %localappdata%\IconCache.db
start explorer.exe
exit
