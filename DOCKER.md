# Docker

This project includes a `Dockerfile` which creates a build container based on `ubuntu-22.04` on the `arm64` platform.  This allows development on `MacOS` to proceed without worrying about the complex dependencies, and without having to pipe data from the internt directly into a shell.

## Build the build container
```
docker build -t sbtc-build .
```

## Run the build container
```
docker run -it -v `pwd`:/sbtc sbtc-build
```

## Build using the build container
```
cd /sbtc
make install
make build
```
