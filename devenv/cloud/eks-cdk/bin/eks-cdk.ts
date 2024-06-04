#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { EksCdkStack } from '../lib/eks-cdk-stack';
import * as blueprints from '@aws-quickstart/eks-blueprints';
import * as loadEnv from '../utils/load-env'
import * as dotenv from 'dotenv'

dotenv.config();

const app = new cdk.App();



const CLUSTER_NAME = loadEnv.CLUSTER_NAME;
const INSTANCE_TYPE = loadEnv.INSTANCE_TYPE;
const DESIRED_SIZE = loadEnv.DESIRED_SIZE;
const MAX_SIZE = loadEnv.MAX_SIZE;



const addOns: Array<blueprints.ClusterAddOn> = [];

if (loadEnv.ARGO_CD_ADDON) {
  addOns.push(new blueprints.addons.ArgoCDAddOn());
}
if (loadEnv.CALICO_OPERATOR_ADDON) {
  addOns.push(new blueprints.addons.CalicoOperatorAddOn());
}
if (loadEnv.METRICS_SERVER_ADDON) {
  addOns.push(new blueprints.addons.MetricsServerAddOn());
}
if (loadEnv.CLUSTER_AUTO_SCALER_ADDON) {
  addOns.push(new blueprints.addons.ClusterAutoScalerAddOn());
}
if (loadEnv.AWS_LOAD_BALANCER_CONTROLLER_ADDON) {
  addOns.push(new blueprints.addons.AwsLoadBalancerControllerAddOn());
}
if (loadEnv.VPC_CNI_ADDON) {
  addOns.push(new blueprints.addons.VpcCniAddOn(
    {
      customNetworkingConfig: {
          subnets: [
              blueprints.getNamedResource("secondary-cidr-subnet-0"),
              blueprints.getNamedResource("secondary-cidr-subnet-1"),
              blueprints.getNamedResource("secondary-cidr-subnet-2"),
          ]
      },
      awsVpcK8sCniCustomNetworkCfg: true,
      eniConfigLabelDef: 'topology.kubernetes.io/zone',
      serviceAccountPolicies: [cdk.aws_iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonEKS_CNI_Policy")]
    }
  ));
}
if (loadEnv.CORE_DNS_ADDON) {
  addOns.push(new blueprints.addons.CoreDnsAddOn());
}
if (loadEnv.KUBKUBE_PROXY_ADDON) {
  addOns.push(new blueprints.addons.KubeProxyAddOn());
}

if (loadEnv.EBS_DRIVER_ADDON) {
  addOns.push(new blueprints.addons.EbsCsiDriverAddOn({
    version: "auto",
    kmsKeys: [
      blueprints.getResource(
        (context) =>
          new cdk.aws_kms.Key(context.scope, "ebs-csi-driver-key", {
            alias: "ebs-csi-driver-key",
          })
      ),
    ],
    storageClass: "gp3",
  }));
}

if(loadEnv.CLOUD_WATCH_ADDON){
  addOns.push(
    new blueprints.CloudWatchLogsAddon({
      logGroupPrefix: '/aws/eks/blueprints-construct-dev',
      logRetentionDays: 30
    })
  )
}



// Deploy Stack
new EksCdkStack(app, 'EksCdkStack', {
  env: {
    account: loadEnv.ACCOUNT,
    region: loadEnv.REGION
  },
  // kubernetes version. Avoid changing from 'auto'
  version: "auto",
  addOns: addOns,
  ecrRepos: loadEnv.ECR_REPOS,

  clusterName: CLUSTER_NAME,
  instanceTypes: [
    {
      instanceType: INSTANCE_TYPE,
      desiredSize: DESIRED_SIZE,
      maxSize: MAX_SIZE
    }
  ]
});