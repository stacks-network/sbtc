import * as cdk from 'aws-cdk-lib';

export interface EmilyStackProps extends cdk.StackProps {

  /**
   * The stageName of the AWS Emily stack.
   */
  readonly stageName: string;

  /**
   * Env is required.
   */
  readonly env: cdk.Environment;
}
