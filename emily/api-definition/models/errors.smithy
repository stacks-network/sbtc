$version: "2.0"

namespace stacks.sbtc

@error("client")
@httpError(400)
structure BadRequestError {
    @required
    message: String
}

@error("client")
@httpError(403)
structure ForbiddenError {
    @required
    message: String
}

@error("client")
@httpError(404)
structure NotFoundError {
    @required
    message: String
}

@error("client")
@httpError(409)
structure ConflictError {
    @required
    message: String
}

@error("client")
@retryable
@httpError(429)
structure ThrottlingError {
    @required
    message: String
}

@error("server")
@httpError(500)
structure ServiceError {
    @required
    message: String
}

@error("server")
@httpError(501)
structure NotImplementedError {
    @required
    message: String
}
