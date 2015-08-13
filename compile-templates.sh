msg(){
	echo -e "\e[31m$@\e[0m"
}

mkdir -p templates

msg Linux 64 Release
scons -j 4 p=x11 target=release tools=no bits=64 colored=yes || exit 1
mv bin/godot.x11.opt.64 templates/linux_x11_64_release
strip templates/linux_x11_64_release
upx templates/linux_x11_64_release

msg Linux 64 Debug
scons -j 4 p=x11 target=release_debug tools=no bits=64 colored=yes || exit 1
mv bin/godot.x11.opt.debug.64 templates/linux_x11_64_debug
strip templates/linux_x11_64_debug
upx templates/linux_x11_64_debug

msg Linux 32 Release
scons -j 4 p=x11 target=release tools=no bits=32 colored=yes || exit 1
mv bin/godot.x11.opt.32 templates/linux_x11_32_release
strip templates/linux_x11_32_release
upx templates/linux_x11_32_release

msg Linux 32 Debug
scons -j 4 p=x11 target=release_debug tools=no bits=32 colored=yes || exit 1
mv bin/godot.x11.opt.debug.32 templates/linux_x11_32_debug
strip templates/linux_x11_32_debug
upx templates/linux_x11_32_debug

msg Windows 64 Release
scons -j 4 p=windows target=release tools=no bits=64 colored=yes || exit 1
mv bin/godot.windows.opt.64.exe templates/windows_64_release.exe
x86_64-w64-mingw32-strip templates/windows_64_release.exe
upx templates/windows_64_release.exe

msg Windows 64 Debug
scons -j 4 p=windows target=release_debug tools=no bits=64 colored=yes || exit 1
mv bin/godot.windows.opt.debug.64.exe templates/windows_64_debug.exe
x86_64-w64-mingw32-strip templates/windows_64_debug.exe
upx templates/windows_64_debug.exe

msg Windows 32 Release
scons -j 4 p=windows target=release tools=no bits=32 colored=yes || exit 1
mv bin/godot.windows.opt.32.exe templates/windows_32_release.exe
i686-w64-mingw32-strip templates/windows_32_release.exe
upx templates/windows_32_release.exe

msg Windows 32 Debug
scons -j 4 p=windows target=release_debug tools=no bits=32 colored=yes || exit 1
mv bin/godot.windows.opt.debug.32.exe templates/windows_32_debug.exe
i686-w64-mingw32-strip templates/windows_32_debug.exe
upx templates/windows_32_debug.exe


