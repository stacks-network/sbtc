$version: "2.0"

namespace stacks.sbtc

use aws.protocols#restJson1

@restJson1
@aws.apigateway#integration(
    type: "aws_proxy",
    // Specifies the integration's HTTP method type (for example, POST). For
    // Lambda function invocations, the value must be POST.
    httpMethod: "POST",
    uri: "arn:${AWS::Partition}:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${OperationLambda.Arn}/invocations",
)
@title("Emily")
service Emily {
    version: "2024-04-26",
    resources: [
        Deposit
        Withdrawal
    ]
}
