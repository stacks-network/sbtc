$version: "2.0"

namespace stacks.sbtc

@idempotent
@http(method: "POST", uri: "/withdrawals")
operation CreateWithdrawal {
    input: CreateWithdrawalInput
    output: WithdrawalData
    errors: [
        ServiceError
        ThrottlingError
        ConflictError
    ]
}

@input
structure CreateWithdrawalInput {
    @required requestId: String
    @required blockHash: Base64EncodedBinary
    @required blockHeight: Integer
    @required recipient: String
    @required amount: Satoshis
    @required parameters: WithdrawalParameters
}

@readonly
@http(method: "GET", uri: "/withdrawals/{id}")
operation GetWithdrawal {
    input := for Withdrawal {
        @httpLabel @required $id
    }
    output: WithdrawalData
    errors: [
        ServiceError
        ThrottlingError
        NotFoundError
    ]
}

@readonly
@http(method: "GET", uri: "/withdrawals")
@paginated(
    inputToken: "nextToken",
    outputToken: "nextToken",
    pageSize: "maxResults",
    items: "deposits",
)
operation GetWithdrawals {
    input: GetWithdrawalsInput
    output: GetWithdrawalsOutput
    errors: [
        ServiceError
        ThrottlingError
        NotFoundError
    ]
}

@input
structure GetWithdrawalsInput {
    @httpQuery("maxResults") maxResults: Integer
    @httpQuery("nextToken") nextToken: String
    @httpQuery("status") status: OpStatus
}

@output
structure GetWithdrawalsOutput {
    nextToken: String
    deposits: WithdrawalBasicInfoList
}

@idempotent
@http(method: "PUT", uri: "/withdrawals")
operation UpdateWithdrawals {
    input: UpdateWithdrawalsInput
    output: UpdateWithdrawalsOutput
    errors: [
        ServiceError
        ThrottlingError
        NotFoundError
        ConflictError
        ForbiddenError
    ]
}

@input
structure UpdateWithdrawalsInput {
    deposits: WithdrawalUpdateList
}

@output
structure UpdateWithdrawalsOutput {
    deposits: WithdrawalDataList
}
