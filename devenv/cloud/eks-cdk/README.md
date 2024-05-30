# sBTC EKS CDK Template

## [1] Overview:
This contains the necessary code to get up and running with an EKS cluster, ECR Repos, and IAM Users with the following select addons:


| Addons Enabled by Default | Addons Disabled by Default   |
|---------------------------|------------------------------|
| ArgoCD                    | AwsLoadBalancerController    |
| CalicoOperator            |                              |
| MetricsServer             |                              |
| ClusterAutoScaler         |                              |
| VpcCni                    |                              |
| CoreDns                   |                              |
| KubeProxy                 |                              |



For a full list of possible addons, please visit the [Amazon EKS Blueprints Addons Page](https://aws-quickstart.github.io/cdk-eks-blueprints/addons/)

### CDK Components:

* EKS Cluster:
    - Since the `ClusterAutoScaler` Addon is turned on by default, it also spins up a single `m5.large` instance. As workloads increase past the resource limit, the cluster autoscales to the necessary amount of nodes
    - 


## [2] Installation:



## [3] Useful commands

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `npx cdk deploy`  deploy this stack to your default AWS account/region
* `npx cdk diff`    compare deployed stack with current state
* `npx cdk synth`   emits the synthesized CloudFormation template
