$version: "2.0"

namespace stacks.sbtc

@idempotent
@http(method: "POST", uri: "/chainstate")
operation CreateChainstate {
    input: CreateChainstateInput
    output: ChainstateData
    errors: [
        ServiceError
        ThrottlingError
        ConflictError
        ForbiddenError
    ]
}

@input
structure CreateChainstateInput {
    @required blockHeight: Integer
    @required blockHash: Base64EncodedBinary
}

@readonly
@http(method: "GET", uri: "/chainstate/{height}")
operation GetChainstate {
    input := for Chainstate {
        @httpLabel @required $height
    }
    output: ChainstateData
    errors: [
        ServiceError
        ThrottlingError
        NotFoundError
    ]
}

@idempotent
@http(method: "PUT", uri: "/chainstate")
operation UpdateChainstate {
    input: UpdateChainstateInput
    output: ChainstateData
    errors: [
        ServiceError
        ThrottlingError
        NotFoundError
        ConflictError
        ForbiddenError
    ]
}

@input
structure UpdateChainstateInput {
    @required blockHeight: Integer
    @required blockHash: Base64EncodedBinary
}
