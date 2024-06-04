import * as dotenv from 'dotenv'
import {DefaultConstants} from './default-constants';


dotenv.config();

export const ACCOUNT = (process.env.AWS_ACCOUNT_ID) ? process.env.AWS_ACCOUNT_ID : DefaultConstants.AWS_ACCOUNT_ID;
export const REGION = (process.env.AWS_REGION) ? process.env.AWS_REGION : DefaultConstants.AWS_REGION;



export const CLUSTER_NAME = (process.env.CLUSTER_NAME) ? process.env.CLUSTER_NAME : DefaultConstants.CLUSTER_NAME
export const INSTANCE_TYPE = (process.env.INSTANCE_TYPE) ? process.env.INSTANCE_TYPE : DefaultConstants.INSTANCE_TYPE


export let DESIRED_SIZE = DefaultConstants.DESIRED_SIZE
if (process.env.DESIRED_SIZE) {
    //try to cast to integer
    try {
        const _d_size = parseInt(process.env.DESIRED_SIZE)
        DESIRED_SIZE = _d_size;
    } catch (error) {
        console.error(`WARN || Env Variable: [DESIRED_SIZE] is not a number. Using ${process.env.DESIRED_SIZE} as DESIRED_SIZE instead`)
    }
}

export let MAX_SIZE = DefaultConstants.MAX_SIZE
if (process.env.MAX_SIZE) {
    //try to cast to integer
    try {
        const _m_size = parseInt(process.env.MAX_SIZE)
        MAX_SIZE = _m_size;
    } catch (error) {
        console.error(`WARN || Env Variable: [MAX_SIZE] is not a number. Using ${process.env.MAX_SIZE} as MAX_SIZE instead`)
    }
}




export let ARGO_CD_ADDON = DefaultConstants.ARGO_CD_ADDON;
if (process.env.ARGO_CD_ADDON) { if (process.env.ARGO_CD_ADDON === "true") ARGO_CD_ADDON = true; else if(process.env.ARGO_CD_ADDON === "false") ARGO_CD_ADDON = false;}

export let CALICO_OPERATOR_ADDON = DefaultConstants.CALICO_OPERATOR_ADDON;
if (process.env.CALICO_OPERATOR_ADDON) { if (process.env.CALICO_OPERATOR_ADDON === "true") CALICO_OPERATOR_ADDON = true; else if(process.env.CALICO_OPERATOR_ADDON === "false") CALICO_OPERATOR_ADDON = false;}

export let METRICS_SERVER_ADDON = DefaultConstants.METRICS_SERVER_ADDON;
if (process.env.METRICS_SERVER_ADDON) { if (process.env.METRICS_SERVER_ADDON === "true") METRICS_SERVER_ADDON = true; else if(process.env.METRICS_SERVER_ADDON === "false") METRICS_SERVER_ADDON = false;}

export let CLUSTER_AUTO_SCALER_ADDON = DefaultConstants.CLUSTER_AUTO_SCALER_ADDON;
if (process.env.CLUSTER_AUTO_SCALER_ADDON) { if (process.env.CLUSTER_AUTO_SCALER_ADDON === "true") CLUSTER_AUTO_SCALER_ADDON = true; else if(process.env.CLUSTER_AUTO_SCALER_ADDON === "false") CLUSTER_AUTO_SCALER_ADDON = false;}

export let AWS_LOAD_BALANCER_CONTROLLER_ADDON = DefaultConstants.AWS_LOAD_BALANCER_CONTROLLER_ADDON;
if (process.env.AWS_LOAD_BALANCER_CONTROLLER_ADDON) { if (process.env.AWS_LOAD_BALANCER_CONTROLLER_ADDON === "true") AWS_LOAD_BALANCER_CONTROLLER_ADDON = true; else if(process.env.AWS_LOAD_BALANCER_CONTROLLER_ADDON === "false") AWS_LOAD_BALANCER_CONTROLLER_ADDON = false;}

export let VPC_CNI_ADDON = DefaultConstants.VPC_CNI_ADDON;
if (process.env.VPC_CNI_ADDON) { if (process.env.VPC_CNI_ADDON === "true") VPC_CNI_ADDON = true; else if(process.env.VPC_CNI_ADDON === "false") VPC_CNI_ADDON = false;}

export let CORE_DNS_ADDON = DefaultConstants.CORE_DNS_ADDON;
if (process.env.CORE_DNS_ADDON) { if (process.env.CORE_DNS_ADDON === "true") CORE_DNS_ADDON = true; else if(process.env.CORE_DNS_ADDON === "false") CORE_DNS_ADDON = false;}

export let KUBKUBE_PROXY_ADDON = DefaultConstants.KUBE_PROXY_ADDON;
if (process.env.KUBKUBE_PROXY_ADDON) { if (process.env.KUBKUBE_PROXY_ADDON === "true") KUBKUBE_PROXY_ADDON = true; else if(process.env.KUBKUBE_PROXY_ADDON === "false") KUBKUBE_PROXY_ADDON = false;}

export let EBS_DRIVER_ADDON = DefaultConstants.EBS_DRIVER_ADDON;
if (process.env.EBS_DRIVER_ADDON) { if (process.env.EBS_DRIVER_ADDON === "true") EBS_DRIVER_ADDON = true; else if( process.env.EBS_DRIVER_ADDON === "false") EBS_DRIVER_ADDON = false;}


export let CLOUD_WATCH_ADDON = DefaultConstants.CLOUD_WATCH_ADDON;
if (process.env.CLOUD_WATCH_ADDON) { if (process.env.CLOUD_WATCH_ADDON === "true") CLOUD_WATCH_ADDON = true; else if( process.env.CLOUD_WATCH_ADDON === "false") CLOUD_WATCH_ADDON = false;}


export const ECR_REPOS = (process.env.ECR_REPOS) ? (process.env.ECR_REPOS as string).split(",").map(s => s.trim()) : DefaultConstants.ECR_REPOS;