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
