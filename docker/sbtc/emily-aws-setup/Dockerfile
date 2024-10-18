FROM sbtc-build:latest AS build

ARG AWS_STAGE=local
ARG TABLES_ONLY=true
WORKDIR /code/sbtc

# TODO: Use make command to generate the cdk template.
RUN pnpm --filter emily-cdk run synth

# Service.
# --------
FROM python:3.12-slim AS emily-aws-setup
WORKDIR /code
COPY --from=build /code/sbtc/docker/sbtc/emily-aws-setup/initialize.py /code/initialize.py
COPY --from=build /code/sbtc/emily/cdk/cdk.out /code/cdk.out
RUN pip3 install boto3
# The local lambda path is not used here because we're only deploying with the
# dynamodb tables. This will need to point to the local lambda zip file
# that was compiled to be deployed.
ENV LOCAL_LAMBDA_PATH=/code/your-compiled-aws-lambda-here.zip
ENV DYNAMODB_ENDPOINT=http://dynamodb:8000
ENV INPUT_CDK_TEMPLATE=/code/cdk.out/EmilyStack.template.json
ENV OUTPUT_CDK_TEMPLATE=/code/cdk.out/EmilyStack.devenv.template.json
ENTRYPOINT ["python3", "/code/initialize.py"]
