import { ApiDefinition } from "aws-cdk-lib/aws-apigateway";
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as fs from 'fs';
import { resolve } from "path";
import { EmilyStackProps } from "./emily-stack-props";
import { Constants } from "./constants";
import { execSync } from "child_process";

/**
 * This class provides utility methods for the Cloud Formation Stack.
 */
export class EmilyStackUtils {

    /*
     * The name of the current stage. Defaults to 'dev'.
     */
    private static stageName?: string;

    /*
     * The AWS account ID. Defaults to the value of the `AWS_ACCOUNT` environment variable, or `CDK_DEFAULT_ACCOUNT` if that is not set.
     */
    private static awsAccount?: string;

    /*
     * The AWS region. Defaults to the value of the `AWS_REGION` environment variable, or `CDK_DEFAULT_REGION` if that is not set.
     */
    private static awsRegion?: string;

    /*
     * Whether only tables should be deployed.
     */
    private static tablesOnly?: boolean;

    /*
     * The number of signer API keys to create.
     */
    private static numSignerApiKeys?: number;

    /*
     * The hosted zone ID.
     */
    private static hostedZoneId?: string;

    /*
     * The custom root domain name.
     */
    private static customRootDomainName?: string;

    /*
     * The string that identifies the source code for the lambda.
     */
    private static lambdaGitIdentifier?: string;

    /*
     * The trusted reorg API key.
     */
    private static trustedReorgApiKey?: string;

    /*
     * The address of the deployer of the sBTC smart contracts.
     */
    private static deployerAddress?: string;

    /*
     * Returns the current stage name.
     */
    public static getStageName(): string {
        this.stageName ??= (process.env.AWS_STAGE ?? Constants.DEFAULT_STAGE_NAME);
        if (this.stageName === undefined) {
            throw new Error('Must define AWS account on either "AWS_ACCOUNT" or "CDK_DEFAULT_ACCOUNT" env variables.');
        }
        return this.stageName;
    }

    /*
     * Returns the AWS account ID.
     */
    public static getAwsAccount(): string {
        this.awsAccount ??= (process.env.AWS_ACCOUNT ?? process.env.CDK_DEFAULT_ACCOUNT);
        if (this.awsAccount === undefined && this.getStageName() !== Constants.LOCAL_STAGE_NAME) {
            throw new Error('Must define AWS account on either "AWS_ACCOUNT" or "CDK_DEFAULT_ACCOUNT" env variables.');
        }
        // If the account is undefined and we're letting it slide set the account to 12 "x"s.
        this.awsAccount ??= "xxxxxxxxxxxx";
        return this.awsAccount;
    }

    /*
     * Returns the AWS region.
     */
    public static getAwsRegion(): string {
        this.awsRegion ??= (process.env.AWS_REGION ?? process.env.CDK_DEFAULT_REGION);
        if (this.awsRegion === undefined && this.getStageName() !== Constants.LOCAL_STAGE_NAME) {
            throw new Error('Must define AWS region on either "AWS_REGION" or "CDK_DEFAULT_REGION" env variables.');
        }

        // If the region is undefined and we're letting it slide, set the region to the
        // standard beta region: us-west-2.
        this.awsRegion ??= "us-west-2";
        return this.awsRegion;
    }

    /*
     * Returns whether only tables should be deployed.
     */
    public static isTablesOnly(): boolean {
        this.tablesOnly ??= (process.env.TABLES_ONLY ?? "false").toLowerCase() === "true";
        return this.tablesOnly;
    }

    /*
     * Returns the number of signer API keys to create.
     */
    public static getNumSignerApiKeys(): number {
        this.numSignerApiKeys ??= parseInt(process.env.NUM_SIGNER_API_KEYS ?? (Constants.DEFAULT_NUM_SIGNER_API_KEYS).toString());
        if (this.numSignerApiKeys === undefined) {
            throw new Error('Must define number of signer API keys');
        }
        return this.numSignerApiKeys
    }

    /*
     * Returns the hosted zone ID or undefined if none is set.
     */
    public static getHostedZoneId(): string | undefined {
        this.hostedZoneId ??= process.env.HOSTED_ZONE_ID;
        return this.hostedZoneId;
    }

    /*
     * Returns the custom root domain name or undefined if none is set.
     */
    public static getCustomRootDomainName(): string | undefined {
        this.customRootDomainName ??= process.env.CUSTOM_ROOT_DOMAIN_NAME;
        return this.customRootDomainName;
    }

    /*
     * Returns the api key that is allowed to make chainstate reorgs.
     */
    public static getTrustedReorgApiKey(): string {
        this.trustedReorgApiKey ??= process.env.TRUSTED_REORG_API_KEY;
        if (this.trustedReorgApiKey === undefined) {
            throw new Error('Must define a trusted reorg api key.');
        }
        return this.trustedReorgApiKey;
    }


    /*
     * Returns the address of the deployer of the sBTC smart contracts.
     */
    public static getDeployerAddress(): string {
        this.deployerAddress ??= process.env.DEPLOYER_ADDRESS;
        if (this.deployerAddress === undefined) {
            throw new Error('Must define a sBTC contracts deployer address.');
        }
        return this.deployerAddress;
    }

    /*
     * Returns true iff the current stack is a development stack / not a production stack.
     */
    public static isDevelopmentStack(): boolean {
        return this.getStageName() === Constants.DEV_STAGE_NAME
            || this.getStageName() === Constants.LOCAL_STAGE_NAME
            || this.getStageName() === Constants.UNIT_TEST_STAGE_NAME
            || this.getStageName() === Constants.TEMP_STAGE_NAME
            || this.getStageName() === Constants.PRIVATE_MAINNET_STAGE_NAME;
    }

    /*
     * Return the path to the resource where the path provided to the input is the
     * path from workspace root.
     */
    public static getPathFromProjectRoot(pathFromProjectRoot: string): string {
        return resolve(__dirname, "../../..", pathFromProjectRoot);
    }

    /*
     * Returns a unique resource name for the given resource ID.
     */
    public static getResourceName(resourceId: string, props: EmilyStackProps): string {
        return [
            resourceId,
            // Allow for this function to work even if you set the cloud formation
            // props manually.
            props.env.account,
            props.env.region,
            props.stageName,
        ].join("-");
    }

    /**
     * @description Returns a unique resource name for the stack given the environment variables.
     * @param {string} stackBaseName the base name of the stack.
     * @returns {string} The name of the resource.
     */
    public static getStackName(stackBaseName: string): string {
        return [
            stackBaseName,
            EmilyStackUtils.getAwsAccount(),
            EmilyStackUtils.getAwsRegion(),
            EmilyStackUtils.getStageName(),
        ].join("-");
    }

    /**
     * @description Returns the architecture that the lambda should run on. Assume ARM64 unless
     * the stack is running locally on an x86 machine.
     * @param {EmilyStackProps} props the Emily Stack props.
     * @returns {lambda.Architecture} the Lambda architecture to use.
     */
    public static getLambdaArchitecture(props: EmilyStackProps): lambda.Architecture {
        return props.stageName === Constants.LOCAL_STAGE_NAME && process.arch.startsWith("x")
            ? lambda.Architecture.X86_64
            : lambda.Architecture.ARM_64;
    }

    /*
     * Returns the string that identifies the source code of the lambda.
     *
     * The following is a possible example of the git identifier:
     * "https://github.com/stacks-network/sbtc.git | testnet-launch-emily-prs | 1ca2a11146b4141c983d026e1275a9bbc517e907"
     */
    public static getLambdaGitIdentifier(): string {
        if (this.lambdaGitIdentifier === undefined) {
            const gitRepo = execSync('git config --get remote.origin.url').toString().trim();
            const gitBranch = execSync('git rev-parse --abbrev-ref HEAD').toString().trim();
            const gitCommit = execSync('git rev-parse HEAD').toString().trim();
            this.lambdaGitIdentifier = `${gitRepo} | ${gitBranch} | ${gitCommit}`;
        }
        if (this.lambdaGitIdentifier === undefined) {
            throw new Error('Failed to get the git identifier for the lambda.');
        }
        return this.lambdaGitIdentifier;
    }

    /**
     * @description Generate an api definition asset from a local OpenAPI definition and modifies the
     * template such that CloudFormation can replace the lambda identifiers with the correct lambda arn.
     * @param {fs.PathOrFileDescriptor} restApiPathOrFileDescriptor the location of the definition asset
     * @param {[lambdaIdentifier: string, lambdaFunction: lambda.Function][]} lambdaFunctionId
     *      lambdaIdentifier, lambdaFunction value pairs to describe which properties to replace and what
     *      they should be replaced with.
     * @returns {ApiDefinition} The name of the resource.
     */
    public static restApiDefinitionWithLambdaIntegration(
        restApiPathOrFileDescriptor: fs.PathOrFileDescriptor,
        apiLambdas: [lambdaIdentifier: string, lambdaFunction: lambda.Alias][],
    ): ApiDefinition {

        // TODO(269): Change Emily API Lambda Integrations to use cdk constructs if possible instead
        // of specification alteration.

        // This whole section is unfortunate but there's not a standard solution. The autogenerated OpenAPI
        // template will always setup the `uri` to have injected substitution with `Fn::Sub`, and the only
        // way to gather the ARN of the lambda as a string at build time is build the whole arn yourself which
        // is worse than this solution; if the arn format changes the api will break without an obvious error.
        // When we get the ARN from lambda.Function object it generates a template function that will gather
        // the ARN and pretend it's a string, so you cannot substitute anything with it directly.
        //
        // In this loop we go through the OpenAPI json and inject it with a parameter such that the
        // `Fn::Sub` can replace with our desired lambda's arn.
        //
        // https://repost.aws/knowledge-center/cloudformation-fn-sub-function
        //
        // If you look at the template that spawns from this you'll see that the `Fn::Sub` actually defines
        // the key to be ANOTHER `Fn::XXX` template function that resolves to be the lambda's Arn.
        //
        // It would be nice if there were a solution that didn't involve doing this ourselves.
        // At the moment, there isn't.
        let apiJsonDefinition = JSON.parse(fs.readFileSync(restApiPathOrFileDescriptor, 'utf-8'));
        let paths = apiJsonDefinition["paths"];
        Object.keys(paths).forEach(path => {
            let verbs = paths[path];
            Object.keys(verbs).forEach(verb => {
                if (Object.keys(verbs[verb]).includes("x-amazon-apigateway-integration")) {
                    let awsIntegration = verbs[verb]["x-amazon-apigateway-integration"];
                    let originalSubString: string = awsIntegration["uri"]["Fn::Sub"];
                    apiLambdas.forEach(([lambdaIdentifier, lambdaFunction]) => {
                        if (originalSubString.includes(`\${${lambdaIdentifier}}`)) {
                            // If the identifier is present in the uri string then generate the template function to
                            // replace the identifier with the lambda arn.
                            //
                            // This will incorrectly handle the already invalid case where two function ARNS are in the uri.
                            // Handling multiple replacements is left as an exercise for the reader.
                            apiJsonDefinition["paths"][path][verb]["x-amazon-apigateway-integration"]["uri"]["Fn::Sub"] =
                                [originalSubString, { [lambdaIdentifier]: lambdaFunction.functionArn }]
                        }
                    })
                }
            })
        })

        // Return the modified template as an ApiDefinition.
        return ApiDefinition.fromInline(apiJsonDefinition)
    }
}
