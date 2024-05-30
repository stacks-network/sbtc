# LOCAL KUBERNETES INSTRUCTIONS


## [I] INSTALLATION

<details>

###  Make sure you have the following installed:

- [1] Install [minikube](https://minikube.sigs.k8s.io/docs/)

https://minikube.sigs.k8s.io/docs/

```
brew install minikube
```

- [2] [Docker Desktop](https://docs.docker.com/desktop/install/mac-install/#system-requirements)

https://docs.docker.com/desktop/install/mac-install/#system-requirements

- [3] Install [`kubectl` & `kubectx`](https://github.com/ahmetb/kubectx) (Kubernetes utils)

https://github.com/ahmetb/kubectx

```
brew install kubectl
brew install kubectx
```

- [4] Set kube-context to point to `minikube`

```
kubectx minikube
```

#### OPTIONAL STEPS:
<details>

- **(OPTIONAL)** [5] Install `k9s` [Kubernetes CLI Viewer](https://k9scli.io/topics/install/)

https://k9scli.io/topics/install/

```
brew install k9s
```

- **(OPTIONAL)** [6] It is highly suggested to also add these aliases to your shell:

```
alias k='kubectl'
alias ka='kubectl apply -f'
alias kg='kubectl get'
alias kp='kubectl port-forward'
alias kd='kubectl delete'
alias kdr='kubectl describe'
alias kdf='kubectl delete -f'
```

</details>

</details>




## [II] DEPLOY

#### [i] Start Minikube:

##### `minikube start`

> Note you might need to increase the disk size of minikube. If there are disk problems, please run `minikube start --disk-size 50000mb` instead and choose the disk size of your preference

#### [ii] Build all containers:

##### `sh build.sh`

#### [iii] Deploy all K8s artifacts:

##### `sh up.sh`

#### [iv] Start to port-forward containers:

##### `sh ./utils/port-forward-containers.sh`

#### [v] Manual testing:

#### - Please visit `http://localhost:3020/` for the Stacks Explorer


#### [vi] **(!! OPTIONAL !!)** Run the automated tests:

##### `sh ./tests/devnet-liveness.sh`


#### [vii] Spin down all K8s artifacts:

##### `sh down.sh`


#### **(!! OPTIONAL !!)** [viii] Delete Minikube Containers:

> Beware that this will permanently remove containers and it will take some time for the containers to be rebuilt again using `build.sh`

##### `sh remove-minikube-containers.sh`



#### [ix] Stop Minikube:

##### `minikube stop`
