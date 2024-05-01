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
