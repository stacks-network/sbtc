To build the build container, do
```
docker build -t sbtc-build .
```
To run the build container, do
```
docker run -it -v `pwd`:/build sbtc-build
```
Once inside the build container, do
```
cd /build
make install
make build
```
