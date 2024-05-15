# DOCKER COMPOSE INSTRUCTIONS

## Spin up all the containers:

###### `sh up.sh`

## Install some testing pkgs:

#### (i) _Postgres Tools_

```
brew install libpq
echo 'export PATH="/opt/homebrew/opt/libpq/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```


## Run the tests:


#### (i) _Run Automated Tests_
######  `sh ./tests/devnet-liveness.sh`


#### (ii) _Manually visit the Mempool and Stacks Explorer Frontends_
######  Mempool Frontend: `http://localhost:3020`
######  Stacks Explorer: `http://localhost:8083`
