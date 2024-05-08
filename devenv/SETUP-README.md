Make sure you have the following installed:

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
`minikube addons enable csi-hostpath-driver`

<!-- [6] Install Postgres tools -->



Some Boilerplate instructions:

* Add Bitnami Repo: `helm repo add bitnami https://charts.bitnami.com/bitnami`
* Start up docker desktop
* `minikube start`
* Check to see if your k8s context is correctly attached to the minikube cluster : `kubectx` (it should say minikube)
* Ensure you set the ctx to minikube: `kubectx minikube` 
* Check to see what namespace you are currently on : `kubens` (should be `default`)

