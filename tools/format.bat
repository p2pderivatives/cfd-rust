if exist "format.bat" (
  cd ..
)

cargo fmt --all -- --emit files

pause
