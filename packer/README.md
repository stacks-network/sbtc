# Machine Image Builder

This directory contains `packer` configuration files for building machine images for the `sBTC` service.


## How to build the image
Creating an image using this files requires the following steps:

- Install packer and AWS CLI
- Go to IAM settings in AWS website, choose user for which you want create credentials, go to Security credentials tab and create new access key
- Fill environment variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` with the values from the previous step
- Run `packer init .` to initialize the packer configuration
- Run `packer validate template.pkr.hcl` to validate the configuration
- Run `packer build template.pkr.hcl` to build the image