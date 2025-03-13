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

  /**
   * The trusted reorg API key.
   */
  readonly trustedReorgApiKey: string;


  /**
   * The address of the deployer of the sBTC smart contracts.
   */
  readonly deployerAddress: string;
}
