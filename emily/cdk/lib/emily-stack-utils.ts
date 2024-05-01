import { ApiDefinition } from "aws-cdk-lib/aws-apigateway";
import * as fs from 'fs';
import { resolve } from "path";
import { EmilyStackProps } from "./emily-stack-props";

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
     * Returns the current stage name.
     */
    public static getStageName(): string {
        this.stageName ??= (process.env.AWS_STAGE ?? "dev");
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
        if (this.awsAccount === undefined) {
            throw new Error('Must define AWS account on either "AWS_ACCOUNT" or "CDK_DEFAULT_ACCOUNT" env variables.');
        }
        return this.awsAccount;
    }

    /*
     * Returns the AWS region.
     */
    public static getAwsRegion(): string {
        this.awsRegion ??= (process.env.AWS_REGION ?? process.env.CDK_DEFAULT_REGION);
        if (this.awsRegion === undefined) {
            throw new Error('Must define AWS region on either "AWS_REGION" or "CDK_DEFAULT_REGION" env variables.');
        }
        return this.awsRegion;
    }

    // TODO: Require access keys for api using sigv4 auth.
    //
    // /*
    // * Returns the website user access key.
    // */
    // public static getWebsiteUserAccessKey(): string | undefined {
    //     this.websiteUserAccessKey ??= (process.env.WEBSITE_USER_ACCESS_KEY
    //         ?? process.env.AWS_DEV_ACCOUNT_ACCESS_KEY);
    //     return this.websiteUserAccessKey;
    // }
    //
    // /*
    // * Returns the website user secret key.
    // */
    // public static getWebsiteUserSecretKey(): string | undefined {
    //     this.websiteUserSecretKey ??= (process.env.WEBSITE_USER_SECRET_KEY
    //         ?? process.env.AWS_DEV_ACCOUNT_SECRET_KEY);
    //     return this.websiteUserSecretKey;
    // }

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
     * @description Generate an api definition asset from a local OpenAPI definition, replacing the lambda
     * integration tags with the appropriate resource values.
     * @param {fs.PathOrFileDescriptor} restApiPathOrFileDescriptor the location of the definition asset
     * @param {string} lambdaFunctionId lambdaFunction Id.
     * @param {EmilyStackProps} props properties of the cloud formation stack.
     * @returns {ApiDefinition} The name of the resource.
     */
    public static restApiDefinitionWithLambdaIntegration(
        restApiPathOrFileDescriptor: fs.PathOrFileDescriptor,
        lambdaFunctionId: string,
        props: EmilyStackProps,
    ): ApiDefinition {

        // Here we generate the lambda invocation uri. The uri is represented with a TOKEN string at build time
        // and resolved at deployment time by CDK. We need to set the api gateway lambda integration values to
        // the lambda uri when we create the apigateway resource, so we calculate it ourselves here.
        const lambdaArn: string = `arn:aws:lambda:${props.env.region}:${props.env.account}:function:${EmilyStackUtils.getResourceName(lambdaFunctionId, props)}`;
        const lambdaUri: string = `arn:aws:apigateway:${props.env.region}:lambda:path/2015-03-31/functions/${lambdaArn}/invocations`;

        // Replace our `${API_LAMBDA_URI}` token with the calculated lambda invokation URI.
        return ApiDefinition.fromInline(JSON.parse(fs.readFileSync(restApiPathOrFileDescriptor, 'utf-8')
                    .replaceAll("${API_LAMBDA_URI}", lambdaUri)))
    }

    /**
     * @description Generate an api definition asset from a local OpenAPI definition, replacing the lambda
     * integration tags with the appropriate resource values.
     * @param {fs.PathOrFileDescriptor} restApiPathOrFileDescriptor the location of the definition asset
     */
    public static restApiDefinition(
        restApiPathOrFileDescriptor: fs.PathOrFileDescriptor,
    ): ApiDefinition {
        // Replace our `${API_LAMBDA_URI}` token with the calculated lambda invokation URI.
        return ApiDefinition.fromInline(JSON.parse(fs.readFileSync(restApiPathOrFileDescriptor, 'utf-8')))
    }
}
