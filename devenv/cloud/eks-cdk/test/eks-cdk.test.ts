import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as EksCdk from '../lib/eks-cdk-stack';
import * as loadEnv from '../utils/load-env';
import * as testutils from './test-utils';



const props: EksCdk.EksCdkStackProps = {
    env: {
        account: loadEnv.ACCOUNT,
        region: loadEnv.REGION
    },
    version: "auto",
    addOns: [],
    ecrRepos: loadEnv.ECR_REPOS,
    clusterName: testutils.CLUSTER_NAME,
    instanceTypes: [
        {
            instanceType: testutils.INSTANCE_TYPE,
            desiredSize: testutils.DESIRED_SIZE,
            maxSize: testutils.MAX_SIZE
        }
    ]
}



describe('EksCdkStack Test', () => {

    it('Should create VPC', async () => {
        // Preliminary
        const app = new cdk.App();
        const stack = new EksCdk.EksCdkStack(app, "TestStack", props);

        // get the k8s sub-template
        
        const template = Template.fromStack(stack.EKS_CLUSTER);


        template.hasResource("AWS::EC2::VPC", {

        });
    });

    it('Should create VPC CIDR Block', async () => {
        // Preliminary
        const app = new cdk.App();
        const stack = new EksCdk.EksCdkStack(app, "TestStack", props);

        // get the k8s sub-template
        
        const template = Template.fromStack(stack.EKS_CLUSTER);


        template.hasResource("AWS::EC2::VPCCidrBlock", {

        });
    });


    it('Should create VPC Subnet', async () => {
        // Preliminary
        const app = new cdk.App();
        const stack = new EksCdk.EksCdkStack(app, "TestStack", props);

        // get the k8s sub-template
        
        const template = Template.fromStack(stack.EKS_CLUSTER);


        template.hasResource("AWS::EC2::Subnet", {

        });
    });


    it('Should create Cluster', async () => {
        // Preliminary
        const app = new cdk.App();
        const stack = new EksCdk.EksCdkStack(app, "TestStack", props);

        // get the k8s sub-template
        
        const template = Template.fromStack(stack.EKS_CLUSTER);


        template.hasResource("Custom::AWSCDK-EKS-Cluster", {

        });
    });

    it('Should create Cluster KMS Key', async () => {
        // Preliminary
        const app = new cdk.App();
        const stack = new EksCdk.EksCdkStack(app, "TestStack", props);

        // get the k8s sub-template
        
        const template = Template.fromStack(stack.EKS_CLUSTER);


        template.hasResource("AWS::KMS::Key", {

        });
    });


    it('Should create Nodegroup', async () => {
        // Preliminary
        const app = new cdk.App();
        const stack = new EksCdk.EksCdkStack(app, "TestStack", props);

        // get the k8s sub-template
        
        const template = Template.fromStack(stack.EKS_CLUSTER);


        template.hasResource("AWS::EKS::Nodegroup", {

        });
    });

    it('Should create Addons', async () => {
        // Preliminary
        const app = new cdk.App();
        const stack = new EksCdk.EksCdkStack(app, "TestStack", props);

        // get the k8s sub-template
        
        const template = Template.fromStack(stack.EKS_CLUSTER);


        template.hasResource("Custom::AWSCDK-EKS-KubernetesResource", {

        });
    });


    it('Should create ECR Repos', async () => {
        // Preliminary
        const app = new cdk.App();
        const stack = new EksCdk.EksCdkStack(app, "TestStack", props);

        // get the k8s sub-template
        
        const template = Template.fromStack(stack);


        template.hasResource("AWS::ECR::Repository", {

        });
    });

})