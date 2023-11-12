#!/bin/bash

# Specify the target directory
target_dir="/c/Users/Administrator/Desktop/dynamic_patch/dependencies/mingw64"

# List of packages to download
packages=(
    mingw-w64-x86_64-bzip2-1.0.8-2
    mingw-w64-x86_64-expat-2.5.0-1
    mingw-w64-x86_64-gettext-0.21.1-1
    mingw-w64-x86_64-gmp-6.2.1-5
    mingw-w64-x86_64-isl-0.26-1
    mingw-w64-x86_64-libffi-3.4.4-1
    mingw-w64-x86_64-libiconv-1.17-3
    mingw-w64-x86_64-libsystre-1.0.1-4
    mingw-w64-x86_64-libtre-git-r128.6fb7206-2
    mingw-w64-x86_64-mpc-1.3.1-1
    mingw-w64-x86_64-mpdecimal-2.5.1-1
    mingw-w64-x86_64-mpfr-4.2.0.p9-1
    mingw-w64-x86_64-ncurses-6.4.20230211-1
    mingw-w64-x86_64-openssl-3.1.0-1
    mingw-w64-x86_64-python-3.10.11-1
    mingw-w64-x86_64-readline-8.2.001-6
    mingw-w64-x86_64-sqlite3-3.42.0-1
    mingw-w64-x86_64-tcl-8.6.12-2
    mingw-w64-x86_64-termcap-1.3.1-6
    mingw-w64-x86_64-tk-8.6.12-1
    mingw-w64-x86_64-tzdata-2023c-1
    mingw-w64-x86_64-windows-default-manifest-6.4-4
    mingw-w64-x86_64-xxhash-0.8.1-2
    mingw-w64-x86_64-xz-5.4.3-1
    mingw-w64-x86_64-zlib-1.2.13-3
    mingw-w64-x86_64-zstd-1.5.5-1
    mingw-w64-x86_64-binutils-2.41-2
    mingw-w64-x86_64-crt-git-11.0.0.r147.gddc5b0f6e-1
    mingw-w64-x86_64-gcc-13.2.0-2
    mingw-w64-x86_64-gcc-ada-13.2.0-2
    mingw-w64-x86_64-gcc-fortran-13.2.0-2
    mingw-w64-x86_64-gcc-libgfortran-13.2.0-2
    mingw-w64-x86_64-gcc-libs-13.2.0-2
    mingw-w64-x86_64-gcc-objc-13.2.0-2
    mingw-w64-x86_64-gdb-13.2-3
    mingw-w64-x86_64-gdb-multiarch-13.2-3
    mingw-w64-x86_64-headers-git-11.0.0.r147.gddc5b0f6e-1
    mingw-w64-x86_64-libgccjit-13.2.0-2
    mingw-w64-x86_64-libmangle-git-11.0.0.r147.gddc5b0f6e-1
    mingw-w64-x86_64-libwinpthread-git-11.0.0.r147.gddc5b0f6e-1
    mingw-w64-x86_64-make-4.4-2
    mingw-w64-x86_64-pkgconf-1~2.0.3-1
    mingw-w64-x86_64-tools-git-11.0.0.r147.gddc5b0f6e-1
    mingw-w64-x86_64-winpthreads-git-11.0.0.r147.gddc5b0f6e-1
    mingw-w64-x86_64-winstorecompat-git-11.0.0.r147.gddc5b0f6e-1
)

# Download packages and copy to the target directory
for package in "${packages[@]}"; do
    pacman -S --downloadonly "$package"
done

# Move downloaded packages to the target directory
mv /var/cache/pacman/pkg/*.pkg.tar.zst "$target_dir"

echo "Packages downloaded and copied to $target_dir"