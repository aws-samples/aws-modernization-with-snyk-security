from pathlib import Path

from aws_cdk import (
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_codepipeline as pipeline,
    aws_codecommit as codecommit,
    aws_codebuild as codebuild,
    aws_codepipeline_actions as cpactions,
    aws_ssm as ssm,
    aws_s3 as s3,
    aws_logs as logs,
    core
)
import os

class SnykCodeartifactStack(core.Stack):

    def __init__(self, scope: core.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        #### PARAMETERS ###
        # TODO: Define Stack Parameters here, before sign off. Blank out these parameters
        # 1. Arn of the CodeCommit repository to be scanned
        # 2. Trail log bucket name, the name of the bucket to be created for the Codepipeline artifacts
        # 3. CodeArtifact Repo name, the name of the CA 
        # 4. CodeArtifact Domain name, the domain name of the created CA 
        codecommit_arn = ''
        artifact_bucket_name = ''
        codeartifact_repo_name = 'demo-domain'
        codeartifact_domain_name = 'pypi-store'
        codecommit_reponame = codecommit_arn.split(':')[5]
        account = os.environ['CDK_DEFAULT_ACCOUNT']
        region = os.environ['CDK_DEFAULT_REGION']
        projectname='CodeAritfactDemo'

        
        # Artifact Bucket
        artifact_bucket = s3.Bucket(
            self,
            "ArtifactBucket",
            bucket_name=artifact_bucket_name,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=True,
                block_public_policy=True,
                ignore_public_acls=True,
                restrict_public_buckets=True,
            ),
            encryption=s3.BucketEncryption.S3_MANAGED,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
            removal_policy=core.RemovalPolicy.DESTROY,
        )


        # Event Rule
        snyk_pipeline_rule = events.Rule(
            self,
            "SnykPipelineSchedule",
            description="A daily triggered rule to kick off the artifact scan",
            enabled=True,
            schedule=events.Schedule.expression('rate(1 day)')
        )

        snyk_cw_role = iam.Role(
            self,
            "snyk_cw_role",
            assumed_by=iam.ServicePrincipal('events.amazonaws.com')
        )

        snyk_cw_role_policy = iam.Policy(
            self,
            'SnykCWRolePolicy',
            policy_name = 'cwe-pipeline-execution',
            document = iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions = ["codepipeline:StartPipelineExecution"],
                            # TODO: Reference the pipeline created below
                            resources = ["*"]
                        )
                    ]
            )
        )
        snyk_cw_role.attach_inline_policy(snyk_cw_role_policy)

        codebuild_log_group = logs.LogGroup(
            self,
            'CodeBuildLogGroup',
            log_group_name = 'snyk-pypi-ca-logs',
            retention = logs.RetentionDays('THREE_MONTHS'),
            removal_policy=core.RemovalPolicy.DESTROY,
        )

        codebuild_service_role = iam.Role(
            self,
            "codebuild_service_role",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal('codebuild.amazonaws.com'),
                iam.ServicePrincipal('codepipeline.amazonaws.com')
            )
        )
        codebuild_service_role_policy = iam.Policy(
            self,
            'SnykCodeBuildRolePolicy',
            policy_name = 'codebuildservicepolicy',
            document = iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            sid = 'CWLogsPermissions',
                            actions = [
                                "logs:CreateLogStream",
                                "logs:PutLogEvents"
                                ],
                            resources = [codebuild_log_group.log_group_arn],
                            effect=iam.Effect.ALLOW,
                        ),
                        iam.PolicyStatement(
                            sid = 'CodeCommitActions',
                            actions = [
                                'codecommit:GitPull',
                                'codecommit:GetBranch',
                                'codecommit:GetCommit',
                                'codecommit:GetUploadArchiveStatus',
                                'codecommit:UploadArchive'
                                ],
                            resources = [codecommit_arn],
                            effect=iam.Effect.ALLOW,
                        ),
                        iam.PolicyStatement(
                            sid = 'CodeBuildActions',
                            actions = [
                                'ssm:GetParam*',
                                'codebuild:BatchGetBuilds',
                                "codebuild:StartBuild",
                                'codebuild:BatchGetBuildBatches',
                                'codebuild:StartBuildBatch'
                                ],
                            resources = ['*'],
                            effect=iam.Effect.ALLOW,
                        ),
                        iam.PolicyStatement(
                            sid = 'S3Permissions',
                            actions = [
                                's3:Get*',
                                's3:Put*'
                                ],
                            resources=[
                                f"arn:aws:s3:::{artifact_bucket_name}",
                                f"arn:aws:s3:::{artifact_bucket_name}/*",
                                ],
                            effect=iam.Effect.ALLOW,
                        ),
                        iam.PolicyStatement(
                            sid = 'CodeArtifactList',
                            actions = [
                                'codeartifact:Describe*',
                                'codeartifact:Get*',
                                'codeartifact:List*',
                                'codeartifact:ReadFromRepository',
                                'codeartifact:GetAuthorizationToken'
                                ],
                            resources = ['*'],
                            effect=iam.Effect.ALLOW,
                        ),
                        iam.PolicyStatement(
                            sid = 'STStoken',
                            actions = ['sts:GetServiceBearerToken'],
                            resources = ['*'],
                            effect=iam.Effect.ALLOW,
                            conditions={
                            "StringEqualsIfExists": {"sts:AWSServiceName": "codeartifact.amazonaws.com"}
                            },
                        ),
                    ]
            )
        )
        codebuild_service_role.attach_inline_policy(codebuild_service_role_policy)

        snyk_build_project= codebuild.PipelineProject(
            self, 
            'snykBuild',
            build_spec= codebuild.BuildSpec.from_object(
            {
                "version": '0.2',
                "env": {
                    "parameter-store":{
                        "SNYK_TOKEN": 'snykAuthToken',
                        "SNYK_ORG": 'snykOrg'
                    }
                },
                "phases":{
                    "install":{
                        "commands":[
                            "echo 'installing Snyk'",
                            "npm install -g snyk"
                        ]
                    },
                    "pre_build":{
                        "commands":[
                            "echo 'authorizing Snyk'",
                            "snyk config set api=$SNYK_TOKEN",
                            "date=`date +%Y-%m-%d-%H%M%S`",
                            "echo '*** Pulling packages from codeartifact ***'",
                            "python list_repos.py",
                            "echo '*** Updating pip ***'",
                            "pip install --upgrade pip",
                            "pip install --upgrade awscli"
                        ]
                    },
                    "build":{
                        "commands":[
                            "echo '*** Log in to AWS CodeArtifact ***'",
                            "aws codeartifact login --tool pip --repository $repository --domain $domainName --domain-owner $domainOwner",
                            "echo '***** Running pip install *****'",
                            "python pip_install.py",
                            "echo '***** Starting Snyk Security Scan *****'",
                            "snyk monitor --file=requirements.txt --package-manager=pip --org=$SNYK_ORG --project-name=$projectname --skip-unresolved"
                        ]
                    },
                    "post_build":{
                        "commands":[
                            "echo '***** Scan completed, sending requirements to s3 *****'",
                            "aws s3 mv requirements.txt s3://$artifactbucket/outputs/$date/requirements.txt",
                            "aws s3 mv errors.txt s3://$artifactbucket/outputs/$date/errors.txt",
                            "echo '***** Build completed *****'"
                        ]
                    }
                }
            }
            ),
            environment = codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.AMAZON_LINUX_2_3,
                compute_type=codebuild.ComputeType.LARGE,
                environment_variables = {
                    'domainName': codebuild.BuildEnvironmentVariable(
                        value=codeartifact_domain_name
                    ),
                    'domainOwner': codebuild.BuildEnvironmentVariable(
                        value=account
                    ),
                    'repository': codebuild.BuildEnvironmentVariable(
                        value=codeartifact_repo_name
                    ),
                    'projectname': codebuild.BuildEnvironmentVariable(
                        value=projectname
                    ),
                    'artifactbucket': codebuild.BuildEnvironmentVariable(
                        value=artifact_bucket_name
                    ),
                }
            ),
            logging = codebuild.LoggingOptions(
                cloud_watch = codebuild.CloudWatchLoggingOptions(
                    log_group = codebuild_log_group
                    )
                ),
            role = codebuild_service_role
            )
        source_artifact = pipeline.Artifact()
        snyk_pipeline = pipeline.Pipeline(
            self,
            'snyk_pipeline',
                stages =[
                    pipeline.StageProps(
                        stage_name = 'sourcestage',
                        actions=[
                            cpactions.CodeCommitSourceAction(
                                action_name='codecommit-source',
                                output=source_artifact,
                                repository=codecommit.Repository.from_repository_name(self,'cc_repository',codecommit_reponame),
                                branch='master'
                            )
                        ]
                    ),
                    pipeline.StageProps(
                        stage_name='build',
                        actions= [
                            cpactions.CodeBuildAction(
                                action_name='SnykStage',
                                input=source_artifact,
                                project=snyk_build_project,
                                check_secrets_in_plain_text_env_variables = True,
                                run_order = 2
                            )
                        ]
                    )
                ],
                pipeline_name = "SnykCodeArtifactPipeline"
            )