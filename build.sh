#!/bin/bash -x

if [ ! $2 ]; then
  echo "Usage $0 <Release|Debug> <InstallDir>"
  exit 0
fi

error()
{
  popd
  exit 1
}

# Build libuauth
pushd libuauth
bash ./build.sh $1 || error
popd

# Build
autoreconf --install || error
./configure --with-ssl --prefix=$2 || error
make -j5 || error
make install || error
chrpath -r \$ORIGIN/../lib $2/sbin/reTurnServer || error
cp ./libuauth/build/libuauth.so $2/lib/ || error

mv $2/sbin $2/bin
mv $2/bin/reTurnServer $2/bin/return
