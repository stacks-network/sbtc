#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { EmilyStack } from '../lib/emily-stack';
import { EmilyStackUtils } from '../lib/emily-stack-utils';

const app = new cdk.App();
new EmilyStack(app, 'EmilyStack', {
    stackName: EmilyStackUtils.getStackName("EmilyApiStack"),
    stageName: EmilyStackUtils.getStageName(), // Default to dev stage.
    env: {
        account: EmilyStackUtils.getAwsAccount(),
        region: EmilyStackUtils.getAwsRegion()
    },
});
