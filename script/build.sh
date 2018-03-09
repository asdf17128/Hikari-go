#!/bin/bash
home=/Users/yukinomiu/go/src/hikari-go
version=`cat $home/script/version.txt`
client_home=$home/command/hikari-client
server_home=$home/command/hikari-server
target=$home/target
config=$home/config

# clean
echo 'clean target directory...'
rm $target/*

function build() {
    CGO_ENABLED=0 GOOS=$1 GOARCH=$2 go build -ldflags "-s -w" -o $target/$3
}

# darwin
echo 'build darwin executable files...'
cd $client_home
build darwin amd64 hikari-client-darwin-x64-$version
build darwin 386 hikari-client-darwin-x86-$version
cd $server_home
build darwin amd64 hikari-server-darwin-x64-$version
build darwin 386 hikari-server-darwin-x86-$version

# linux
echo 'build linux executable files...'
cd $client_home
build linux amd64 hikari-client-linux-x64-$version
build linux 386 hikari-client-linux-x86-$version
cd $server_home
build linux amd64 hikari-server-linux-x64-$version
build linux 386 hikari-server-linux-x86-$version

# windows
echo 'build windows executable files...'
cd $client_home
build windows amd64 hikari-client-windows-x64-$version.exe
build windows 386 hikari-client-windows-x86-$version.exe
cd $server_home
build windows amd64 hikari-server-windows-x64-$version.exe
build windows 386 hikari-server-windows-x86-$version.exe

# copy config
echo 'copy config files...'
cp $config/* $target/

echo 'finished'
