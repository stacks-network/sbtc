# Emily API

## Repo Structure

The Emily API has two parts:
1. The Handler - specified within the `handler` rust crate in this directory
1. The Infrastructure - specified within the `cdk` via AWS' typescript CDK.

## Handler

The emily handler is written in a rust crate that utilizes the `warp` and `utoipa` crates to create a filter based api server and generate an openapi template for the API that it serves respectively. As of writing this, the openapi template is published to `.generated-sources/emily/openapi`.

### Compilation

There are two binaries that this handler can create:
1. `emily-server` - a warp server that expects to run on a host
2. `emily-lambda` - a warp lambda that expects to run on an AWS lambda

For testing it makes the most sense to run the server version, but for deployment the lambda version needs to be compiled explicitly for deployment on an AWS lambda; it needs to be compiled with [`cargo lambda`](https://www.cargo-lambda.info/), and due to a limitation of a dependency of the `sbtc` crate it can only be compiled for `x86` processors.

The command to compile the lambda for deployment is as follows:

```bash
cargo lambda build --bin emily-lambda [--release] --output-format zip --x86-64
```

This file is referenced within the cdk and deployed to the lambda.

### Lambda Configuration

The emily lambda takes in config values via the environment it's deployed on. As of writing this there are 6 environment values that are passed to emily during deployment. This can be found within the cdk definition.

```javascript
environment: {
    DEPOSIT_TABLE_NAME: depositTableName,
    WITHDRAWAL_TABLE_NAME: withdrawalTableName,
    CHAINSTATE_TABLE_NAME: chainstateTableName,
    LIMIT_TABLE_NAME: limitTableName,
    IS_LOCAL: "true" | "false",
    TRUSTED_REORG_API_KEY: trustedReorgApiKey,
},
```

All these parameters are consumed via the `context.rs` file within the handler crate.

The table names specify the dynamodb tables that the API uses to store data, and the trusted reorg api key is the api key that has the special ability to intiate a reorg in the chainstate. More on that later.

## CDK

The Emily Typescript CDK deploys a number of resources:

1. Every DynamoDB table used by Emily
2. The Emily rust lambda handler
3. The API gateway instance that connects to the lambda and all connected API keys

### Template Configuration

As of writing this the below list of environment variables is the exhaustive set of configuration options of the cdk template. All of these and the nuances of their inclusion can be found within `cdk/lib/emily-stack-util.ts`.

```bash
# The stage to deploy to
AWS_STAGE=dev

# The AWS region on which to deploy the stack
AWS_REGION=us-west-2

# The number of API keys to generate
NUM_SIGNER_API_KEYS=15

# Your domain name.
CUSTOM_ROOT_DOMAIN_NAME=<your-url.com>

# the hosted zone id of the domain name, taken from AWS console after
# purchasing your domain.
HOSTED_ZONE_ID=Z00000000000000000000

# The api key that you trust to indicate valid reorgs on the
# api chainstate.
TRUSTED_REORG_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Whether to deploy only the dynamodb tables - helpful for testing.
TABLES_ONLY=false
```

> **Caution:** when deploying to a stage that's deemed to be for an active development stack (`dev`, `local`, `unit-test`) all persistent resources will be set to be deleted when the stack is redeployed or deleted. It's not recommended to use any of these environments for anything you want to be remotely persistent.

### Custom Domains

When you specify a custom domain name for your stack you need to also provide the hosted zone id which you can find in AWS console. You need to have purchased this before attempting to deploy the API to a custom domain. If you don't provide a custom root domain name it won't bother attaching the api to a custom domain, so you're safe if you don't want to purchase one.

The custom domain will generate a different api based on the stage that you deploy to. Lets assume your custom domain is `example.com`

- stage = `prod` -> `example.com`
- stage = `dev` -> `dev.example.com`
- stage = `anything-else` -> `anything-else.example.com`

### Api Keys

The template will deploy the number of API key specified by the `NUM_SIGNER_API_KEYS` environment variable. If you redeploy the stack with a lower number of api keys than it had previously the number of api keys in the set will be reduced, and those that were deleted will be deleted forever.

## Deployment

The following steps, in order, need to occur for the Emily API to be deployed.

1. The OpenAPI template for Emily is compiled
2. Emily API is compiled as a lambda
3. CDK template is generated
4. CDK template is deployed to AWS

Generally steps 3 and 4 occur in the same step, but understanding that they are separate is helpful for debugging.

### Troubleshooting

#### Finding Your Resources

The resources for a specific emily deployment have the following name format, with very few exceptions if any: `{base-name}-{account-id}-{region}-{stage}`. So a beta deployment of Emily on account `XXXXXXXXXXXX` would have its chaistate table named `ChainstateTable-XXXXXXXXXXXX-us-west-2-beta`.

#### Logs

The only resource that provides logs is the `OperationLambda` which is the handler lambda referenced above. The logs will be within the region that the lambda was deployed to and given a name following the standard emily resource format.

#### Lambda Rollback

The emily lambda is deployed as a new version every time its deployed, preserving its previous deployment. The apigateway instance points to the deployed lamdba via the alias `Current`, so if you need to rollback the emily lambda to a previous version just redirect the `Current` alias to the version you'd like to rollback to.

Each version is given a description that indicates the branch and commit of the emily that was deployed, with the caveat that this commit hash does not encapsulate any local changes that were in the repository when the lambda was deployed. You should only be deploying a production lambda from a clean checkout of your git repository on your chosen branch.

### Common Questions

#### Why Call It Emily?

The Emily API is given an indirect name because it handles more than just Deposits and Withdrawals; it can detect the health of the system and will likely be extended to handle more as user requirements mature. It was once called the “Revealer API”, which stopped making sense after a few design changes, and then “Deposit API” which also stopped making sense after a few changes. The most obvious choice “sBTC API” gives the wrong impression of what the API is responsible for as well, since the API itself isn’t managing the vast majority of the protocol.

Large companies name their APIs after something loosely related but ambiguous enough that extensions of the API don’t make the original name of the API misleading. Following this, we chose “Emily” after [Emily Warren Roebling](https://en.wikipedia.org/wiki/Emily_Warren_Roebling) who was the liaison between the builders and chief engineer, her husband, of the brooklyn bridge. She was, in effect, the supervisor of the bridge’s construction; similarly, the Emily API supervises the sBTC bridge and liaises between the users of the protocol and the sBTC signers.

#### Why Write the Handler in Rust?

We chose to write the handler in rust to restrict the codebase to as few languages as possible, and to utilize the same rust crate that extracts data about the bitcoin transactions in the signer within the API. This code is hard to get right, and not worth duplicating in multiple languages.
