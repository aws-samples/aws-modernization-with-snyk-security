#!/usr/bin/env python3

from aws_cdk import core


from cdk_stack_deploy.cdk_snyk_stack import CdkSnykStack
from cdk_stack_deploy.cdk_snyk_codeartifact_stack import SnykCodeartifactStack

app = core.App()
CdkSnykStack(app,'cdk-snyk-stack')
SnykCodeartifactStack(app, "cdk-snyk-ca-stack")

app.synth()
