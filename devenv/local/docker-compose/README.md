# DOCKER COMPOSE INSTRUCTIONS


## [1] Build all containers:

##### `sh build.sh`

## [2] Spin up all containers:

##### `sh up.sh`


## [3] Install some testing pkgs:

#### (i) _Postgres Tools_

You can install Postgres completely: [https://www.postgresql.org/download/](https://www.postgresql.org/download/) (recommended for Windows)

Or you can install just the Postgres testing tools for the CLI (recommended for Mac & Linux)

* Windows: https://www.postgresql.org/download/windows/

* Mac (with `zsh`):

```
brew install libpq
echo 'export PATH="/opt/homebrew/opt/libpq/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

* Linux: 

```
sudo apt-get install libpq5
sudo apt-get install libpq-dev
```



## [4] Run the tests:


#### (i) _Run Automated Tests_
#####  `sh ./tests/devnet-liveness.sh`


#### (ii) _Manually visit the Mempool and Stacks Explorer Frontends_
#####  Stacks Explorer: `http://localhost:3020`
#####  Mempool Frontend: `http://localhost:8083`


## [5] Spin down containers:

##### `sh down.sh`