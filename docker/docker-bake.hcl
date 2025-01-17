target "emily-aws-setup" {
    cache-to = [
        "type=gha,ignore-error=true,mode=max,scope=emily-aws-setup"
    ]
    cache-from = [
        "type=gha,scope=emily-aws-setup"
    ]
}