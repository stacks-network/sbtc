# sBTC DEVNET

<!-- ## This section contains all necessary information on how to spin up an sBTC Devnet using both Docker Compose or Kubernetes locally or in the cloud -->
### This section contains all necessary information on how to spin up an sBTC Devnet using Docker Compose

#

<!-- > To setup locally, you can use Docker Compose or Minikube (for K8s setup) -->


### **LOCAL DEVNET**

#### - Docker Compose

##### Inside of [local](local/) you will find the [docker-compose](local/docker-compose/) folder which contains all the necessary containers and the [docker-compose.yml](local/docker-compose/docker-compose.yml). For for detailed instructions on how to get started, please refer to [INSTRUCTIONS.md](local/docker-compose/INSTRUCTIONS.md)

<!-- ##### - Minikube -->

<!-- ### CLOUD DEVNET
##### - EKS -->

<!-- Make sure you have the following installed:

[1] minikube

* Install: `brew install minikube`

[2] Docker Desktop
* https://docs.docker.com/desktop/install/mac-install/#system-requirements

[3] `kubectl` (Kubernetes cli tool)

* Install: `brew install kubectl`

* Install: `brew install kubectx`

* (OPTIONAL) I highly suggest you also add these aliases to your `.zshrc` (don't forget to `source ~/.zshrc`):

```
alias k='kubectl'
alias ka='kubectl apply -f'
alias kg='kubectl get'
alias kp='kubectl port-forward'
alias kd='kubectl delete'
alias kdr='kubectl describe'
alias kdf='kubectl delete -f'
```

[4] Helm

* Install: `brew install helm`

[5] Install Minikube Addons

`minikube addons enable volumesnapshots`
`minikube addons enable csi-hostpath-driver` -->

<!-- [6] Install Postgres tools -->



<!-- Some Boilerplate instructions:

* Add Bitnami Repo: `helm repo add bitnami https://charts.bitnami.com/bitnami`
* Start up docker desktop
* `minikube start`
* Check to see if your k8s context is correctly attached to the minikube cluster : `kubectx` (it should say minikube)
* Ensure you set the ctx to minikube: `kubectx minikube` 
* Check to see what namespace you are currently on : `kubens` (should be `default`)
 -->
