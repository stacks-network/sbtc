


export const DefaultConstants = {
    AWS_ACCOUNT_ID: process.env.CDK_DEFAULT_ACCOUNT,
    AWS_REGION: process.env.CDK_DEFAULT_REGION,
    
    CLUSTER_NAME: "sbtc-cluster",

    INSTANCE_TYPE: "m5.large",
    DESIRED_SIZE: 2,
    MAX_SIZE: 4,

    ARGO_CD_ADDON: true,
    CALICO_OPERATOR_ADDON: true,
    METRICS_SERVER_ADDON: true,
    CLUSTER_AUTO_SCALER_ADDON: true,
    AWS_LOAD_BALANCER_CONTROLLER_ADDON: false,
    VPC_CNI_ADDON: true,
    CORE_DNS_ADDON: true,
    KUBE_PROXY_ADDON: true,
    EBS_DRIVER_ADDON: true,
    CLOUD_WATCH_ADDON: true,
    
    ECR_REPOS: [
        "stacks",
        "stacks-api", 
        "stacks-explorer", 
        "bitcoin", 
        "bitcoin-miner-sidecar",
        "electrs",
        "nakamoto-signer"
    ]
}