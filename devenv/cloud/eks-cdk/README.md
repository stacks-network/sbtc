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
| EBSDriver                 |                              |
| CloudWatch                |                              |



For a full list of possible addons, please visit the [Amazon EKS Blueprints Addons Page](https://aws-quickstart.github.io/cdk-eks-blueprints/addons/)

### CDK Components:

* EKS Cluster:
    - Comes with an on-demand nodegroup with a default instance type of `m5.large` with a desired size of 2 and a max size of 4
    - For the default addons, please refer to Section [1]
* ECR Repos:
    - These are the default ECR Repos:
        - stacks
        - stacks-api
        - stacks-explorer
        - bitcoin
        - bitcoin-miner-sidecar
        - electrs
        - nakamoto-signer
* IAM User which has ECR Push access



## [2] Installation:

> This Section assumes you have the `aws` cli installed

* Ensure you have `make`, `kubectl` and `node` installed

* Install aws cdk `v2.133.0` installed:
    - `npm install -g aws-cdk@2.133.0   # may require sudo (Ubuntu) depending on configuration`
    - Any other version will lead to dependency conflict with the AWS Blueprint library

* Install npm deps:
    - `npm install`

* Bootstrap AWS CDK:
    - `cdk bootstrap aws://<YOUR AWS ACCOUNT ID>/<AWS REGION>`

* Copy over the example env file from [./sample-configs/.env-sample-eks](sample-configs/.env-sample-eks) into root directory and rename to `.env`
    - Make sure you change `AWS_ACCOUNT_ID` from "xxxxxxxxxxxx" to your specific account id

* Deploy:
    - `cdk deploy --all`
    - Press `y` for the incoming prompts


When the deploy is finished, you will see this in the terminal:

```
Outputs:
east-test-1.easttest1ClusterName8D8E5E5E = east-test-1
east-test-1.easttest1ConfigCommand25ABB520 = aws eks update-kubeconfig --name east-test-1 --region us-east-1 --role-arn <ROLE_ARN>
east-test-1.easttest1GetTokenCommand337FE3DD = aws eks get-token --cluster-name east-test-1 --region us-east-1 --role-arn <ROLE_ARN>

Stack ARN:
arn:aws:cloudformation:us-east-1:115717706081:stack/east-test-1/e1b9e6a0-d5f6-11eb-8498-0a374cd00e27
```

Please copy & run the command in the second line to be able to access your cluster locally


## [3] Uninstall:

To delete the Stack, please run: 

`cdk destroy --all`
