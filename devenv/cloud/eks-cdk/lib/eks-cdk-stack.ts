import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as blueprints from '@aws-quickstart/eks-blueprints';
import { KubernetesVersion, CapacityType, NodegroupAmiType } from 'aws-cdk-lib/aws-eks';

export interface InstanceTypeWrapper {
  instanceType: string
  desiredSize: number
  maxSize: number
}


export interface EksCdkStackProps extends cdk.StackProps {
  version: "auto" | KubernetesVersion,
  addOns: Array<blueprints.ClusterAddOn>
  ecrRepos: string[]
  instanceTypes: InstanceTypeWrapper[]
  clusterName: string
}


export class EksCdkStack extends cdk.Stack {

  EKS_CLUSTER: blueprints.EksBlueprint
  ECR_REPOS: cdk.aws_ecr.Repository[]
  IAM_ECR_PUSH_USER: cdk.aws_iam.User


  constructor(scope: Construct, id: string, props: EksCdkStackProps) {
    super(scope, id, props);
    
    this.EKS_CLUSTER = this.createKubernetesCluster(scope, 'sbtc-cluster', props);
    this.ECR_REPOS = this.createEcrRepos(props);
    
    const ecr_resources_list: string[] = this.ECR_REPOS.map(repo => repo.repositoryArn);
    this.IAM_ECR_PUSH_USER = this.createIAMUserWithEcrPushPolicy(props, ecr_resources_list);
  }


  createKubernetesCluster(scope: Construct, clusterStackId: string, props: EksCdkStackProps): blueprints.EksBlueprint {

    blueprints.HelmAddOn.validateHelmVersions = true; // optional if you would like to check for newer versions
    blueprints.HelmAddOn.failOnVersionValidation = false;
    

    const nodeRole = new blueprints.CreateRoleProvider("blueprint-node-role", new cdk.aws_iam.ServicePrincipal("ec2.amazonaws.com"),
    [
        cdk.aws_iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonEKSWorkerNodePolicy"),
        cdk.aws_iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonEC2ContainerRegistryReadOnly"),
        cdk.aws_iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore")
    ]);

    // Instantiated to for helm version check.
    new blueprints.ExternalDnsAddOn({
        hostedZoneResources: [ blueprints.GlobalResources.HostedZone ]
    });



    const CLUSTER_PROVIDER = this.createClusterProvider(props);

    // Create Kuberentes Cluster
    const EksClusterStack = blueprints.EksBlueprint.builder()
            .account(props.env?.account)
            .region(props.env?.region)
            .version(props.version)
            .addOns(...props.addOns)
            .resourceProvider(blueprints.GlobalResources.Vpc, new blueprints.VpcProvider(undefined, {
              primaryCidr: "10.2.0.0/16",
              secondaryCidr: "100.64.0.0/16",
              secondarySubnetCidrs: ["100.64.0.0/24","100.64.1.0/24","100.64.2.0/24"]
            }))
            .resourceProvider("node-role", nodeRole)
            .clusterProvider(CLUSTER_PROVIDER)
            .useDefaultSecretEncryption(true) // set to false to turn secret encryption off (non-production/demo cases)
            .build(scope, clusterStackId);

    return EksClusterStack;
  }

  addGenericNodeGroup(nodeGroupName: string, instanceType: string, desiredSize: number, maxSize: number): blueprints.ManagedNodeGroup {

    return {
        id: nodeGroupName,
        amiType: NodegroupAmiType.AL2_X86_64,
        instanceTypes: [new cdk.aws_ec2.InstanceType(instanceType)],
        desiredSize: desiredSize,
        maxSize: maxSize,
        nodeRole: blueprints.getNamedResource("node-role") as cdk.aws_iam.Role,
        nodeGroupSubnets: { subnetType: cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS },
        launchTemplate: {
            // You can pass Custom Tags to Launch Templates which gets Propogated to worker nodes.
            tags: {
                "Name": nodeGroupName,
                "Type": "Managed-Node-Group",
                "LaunchTemplate": "Custom",
                "Instance": "ONDEMAND"
            },
            requireImdsv2: false
        }
    };
  }

  createClusterProvider(props: EksCdkStackProps): blueprints.GenericClusterProvider {
    const _managedNodeGroups: blueprints.ManagedNodeGroup[] = [];
    for(let i = 0 ; i < props.instanceTypes.length; i++){
      let i_type = props.instanceTypes[i];
      _managedNodeGroups.push(this.addGenericNodeGroup(`on-demand-ng${i+1}`, i_type.instanceType, i_type.desiredSize, i_type.maxSize));
    }

    const clusterProvider = new blueprints.GenericClusterProvider({
        version: KubernetesVersion.V1_29,
        tags: {
            "Name": props.clusterName,
            "Type": "generic-cluster"
        },
        mastersRole: blueprints.getResource(context => {
            return new cdk.aws_iam.Role(context.scope, 'AdminRole', { assumedBy: new cdk.aws_iam.AccountRootPrincipal() });
        }),
        managedNodeGroups: _managedNodeGroups
    });

    return clusterProvider
  }


  createEcrRepos(props: EksCdkStackProps): cdk.aws_ecr.Repository[] {

    const ecr_repos: cdk.aws_ecr.Repository[] = [];

    // Create ECR Repos
    for(let i = 0; i < props.ecrRepos.length; i++){
      let ecr_repo_name = props.ecrRepos[i];
      
      const ecr_repo = new cdk.aws_ecr.Repository(this, `${ecr_repo_name}-repo`, {
        repositoryName: ecr_repo_name,
        removalPolicy: cdk.RemovalPolicy.DESTROY
      });

      ecr_repos.push(ecr_repo);
    }

    return ecr_repos
  }

  createIAMUserWithEcrPushPolicy(props: EksCdkStackProps, ecr_resources_list: string[]): cdk.aws_iam.User {
    // Create an IAM user
    const user = new cdk.aws_iam.User(this, 'PushToECR', {
      userName: 'PUSH-TO-ECR'
    });

    // Define an IAM policy statement that allows push access to the ECR repository
    const pushPolicyStatement = new cdk.aws_iam.PolicyStatement({
      effect: cdk.aws_iam.Effect.ALLOW,
      actions: [
        'ecr:BatchCheckLayerAvailability',
        'ecr:CompleteLayerUpload',
        'ecr:GetDownloadUrlForLayer',
        'ecr:InitiateLayerUpload',
        'ecr:PutImage',
        'ecr:UploadLayerPart'
      ],
      resources: ecr_resources_list
    });

    // Create an IAM policy and attach the policy statement
    const pushPolicy = new cdk.aws_iam.Policy(this, 'EcrPushPolicy', {
      policyName: 'EcrPushPolicy',
      statements: [pushPolicyStatement]
    });

    // Attach this policy to PUSH-TO-ECR user
    user.attachInlinePolicy(pushPolicy);

    return user;
  }


}
