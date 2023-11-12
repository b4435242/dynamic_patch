#!/bin/bash

# Specify the target directory
target_dir="/c/Users/Administrator/Desktop/dynamic_patch/dependencies/mingw64"

# Obtain download URLs for Mingw-w64 GCC toolchain packages
package_urls=$(pacman -Sp mingw-w64-x86_64-toolchain | awk '{print $1}' | sed 's|^file://||')

# Print URLs to the console
echo "Package URLs:"
echo "$package_urls"

# Copy packages to the target directory
echo "Copying packages to $target_dir"
for url in $package_urls; do
    package_file=$(basename "$url")
    cp "$url" "$target_dir/$package_file"
done

echo "Packages copied to $target_dir"


# List of packages to download
packages=(
    mingw-w64-x86_64-tcl-8.6.1-1-any.pkg.tar.zst
    mingw-w64-x86_64-gettext-0.21-1-any.pkg.tar.zst
    mingw-w64-x86_64-openssl-3.0.1-1-any.pkg.tar.zst
    mingw-w64-x86_64-ncurses-6.2-1-any.pkg.tar.zst
    mingw-w64-x86_64-sqlite3-3.36.0-1-any.pkg.tar.zst
    mingw-w64-x86_64-libiconv-1.16-2-any.pkg.tar.zst
    mingw-w64-x86_64-xz-5.4.3-2-any.pkg.tar.zst
    mingw-w64-x86_64-zstd-1.5.0-1-any.pkg.tar.zst
    mingw-w64-x86_64-python-3.9.7-1-any.pkg.tar.zst
    mingw-w64-x86_64-gmp-6.2.1-1-any.pkg.tar.zst
    mingw-w64-x86_64-readline-8.1.1-1-any.pkg.tar.zst
    mingw-w64-x86_64-mpfr-4.2.1-1-any.pkg.tar.zst
    mingw-w64-x86_64-mpdecimal-2.5.1-1-any.pkg.tar.zst
    mingw-w64-x86_64-tzdata-2021b-1-any.pkg.tar.zst
    mingw-w64-x86_64-expat-2.4.1-1-any.pkg.tar.zst
    mingw-w64-x86_64-xxhash-0.8.0-1-any.pkg.tar.zst
    mingw-w64-x86_64-mpc-1.2.1-1-any.pkg.tar.zst
    mingw-w64-x86_64-zlib-1.2.11-12-any.pkg.tar.zst
    mingw-w64-x86_64-bzip2-1.0.8-2-any.pkg.tar.zst
    mingw-w64-x86_64-libtre-git-11.0.0.r147.gddc5b0f6e-1-any.pkg.tar.zst
    mingw-w64-x86_64-libffi-3.4.2-1-any.pkg.tar.zst
    mingw-w64-x86_64-termcap-1.3.1-3-any.pkg.tar.zst
    mingw-w64-x86_64-libsystre-git-11.0.0.r147.gddc5b0f6e-1-any.pkg.tar.zst
    mingw-w64-x86_64-windows-default-manifest-6.4-3-any.pkg.tar.zst
    mingw-w64-x86_64-tk-8.6.12-1-any.pkg.tar.zst
    mingw-w64-x86_64-isl-0.26-1-any.pkg.tar.zst
)

# Download packages and copy to the target directory
for package in "${packages[@]}"; do
    pacman -S --downloadonly "$package"
done

# Move downloaded packages to the target directory
mv /var/cache/pacman/pkg/*.pkg.tar.zst "$target_dir"

echo "Packages downloaded and copied to $target_dir"
