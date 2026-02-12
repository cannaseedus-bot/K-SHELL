@echo off
setlocal enabledelayedexpansion
echo K-UX/π Bootstrap Verification
echo =============================
echo.

if exist k_shell.exe (
  echo [STAGE 0] k_shell.exe found
) else (
  echo [STAGE 0] Not present
)

if exist kux_verifier.exe (
  echo [STAGE 1] kux_verifier.exe found
) else (
  echo [STAGE 1] Missing - run build.bat
)

if exist k_shell_v2.exe (
  echo [STAGE 2] k_shell_v2.exe found
  k_shell_v2.exe --verify
  if !ERRORLEVEL! EQU 0 (
    echo [STAGE 2] Self-verification PASSED
  ) else (
    echo [STAGE 2] Self-verification FAILED
  )
)

echo.
echo Bootstrap Chain Status:
echo ------------------------
if exist k_shell_v2.exe (
  echo Full bootstrap achieved - Stage 2 self-hosting
) else if exist kux_verifier.exe (
  echo Partial bootstrap - Stage 1 verifier ready
) else if exist k_shell.exe (
  echo Stage 0 generator ready
) else (
  echo No bootstrap components found
)
endlocal
