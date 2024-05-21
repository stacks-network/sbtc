# DOCKER COMPOSE INSTRUCTIONS


## [1] Build all containers:

###### `sh build.sh`

## [2] Spin up all the containers:

###### `sh up.sh`


## [3] Install some testing pkgs:

#### (i) _Postgres Tools_

```
brew install libpq
echo 'export PATH="/opt/homebrew/opt/libpq/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```


## [4] Run the tests:


#### (i) _Run Automated Tests_
######  `sh ./tests/devnet-liveness.sh`


#### (ii) _Manually visit the Mempool and Stacks Explorer Frontends_
######  Mempool Frontend: `http://localhost:3020`
######  Stacks Explorer: `http://localhost:8083`


## [5] Spin down containers:

###### `sh down.sh`