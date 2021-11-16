---
title: "ECR Integration"
chapter: true
weight: 58
---

## Architecture
The architecture for this workload is as follows.

## What is Snyk container scanning?
Container images may contain multiple layers. These typically includes the operating system, and application code. Within each of these layers, there is potential to introduce vulnerability in your containers.

When Snyk Container scans an image, it first finds the software installed. For example:

- dpkg, rpm and apk operating systems packages.
- Popular unmanaged software, ie. installed outside a package manager.
- Application packages based on the presence of a manifest file.

After Snyk has the list of installed software, it is cross-referenced against [Snyk Vulnerability DB](https://security.snyk.io/), which combines public sources with proprietary research. Snyk vulnerability DB provides customers with detailed information and remediation guidance for known vulnerabilities.

## What operating systems are supported by Snyk Container scanning?
Snyk detects vulnerabilities in images based on:

- Debian
- Ubuntu
- Centos
- Red Hat Enterprise Linux (including UBI)
- Amazon Linux 2
- SUSE Linux Enterprise Server
- Alpine

> Note: Snyk also supports images using packages from those distributions but without the associated package manager, such as Distroless images.

## Automated Integration with Amazon Elastic Container Registry (ECR) service

Snyk offers customers a seamless means of enabling an ECR integration published as an official [AWS Quick Start](https://aws.amazon.com/quickstart/architecture/snyk-security/). This option may be used instead of the manual process detailed below. 

## Manual Integration with Amazon Elastic Container Registry (ECR) service

In order to integrate ECR with Snyk, you need to first create AWS IAM permissions which allows Snyk to interact with Docker images in ECR.

### Building IAM role using AWS console
1. Login to your AWS console, go to IAM service. 
2. Goto `Policy` and `Create New Policy` with the following JSON
```
{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Sid": "SnykAllowPull",
   "Effect": "Allow",
   "Action": [
    "ecr:GetLifecyclePolicyPreview",
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage",
    "ecr:DescribeImages",
    "ecr:GetAuthorizationToken",
    "ecr:DescribeRepositories",
    "ecr:ListTagsForResource",
    "ecr:ListImages",
    "ecr:BatchCheckLayerAvailability",
    "ecr:GetRepositoryPolicy",
    "ecr:GetLifecyclePolicy"
   ],
   "Resource": "*"
  }
 ]
}
```
3. Now goto the IAM roles section, create a new role under the name `AWSServiceRoleforECR` and attach the policy you created above.

4. After you create the role, you can edit the trust relationship to look like the snippet below
```
{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Principal": {
    "AWS": "arn:aws:iam::198361731867:user/ecr-integration-user"
   },
   "Action": "sts:AssumeRole"
  }
 ]
}
     
```

5. Copy the role ARN which will be used later in the Snyk console.

### Building IAM policy using AWS CLI
> Before following the steps below, make sure your AWS CLI profile has permissions for `CreatePolicy`, `CreateRole` at the very least. For completeness ensure you have `Delete` permissions for IAM roles and policies as well.

1. In the AWS account where you have a Docker image stored in ECR, run the following AWS CLI command:
```
aws iam create-policy --policy-name SnykECRPolicy --policy-document file://snyk-policy.json
```
The content of `snyk-policy.json` file is below:


```
{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Sid": "SnykAllowPull",
   "Effect": "Allow",
   "Action": [
    "ecr:GetLifecyclePolicyPreview",
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage",
    "ecr:DescribeImages",
    "ecr:GetAuthorizationToken",
    "ecr:DescribeRepositories",
    "ecr:ListTagsForResource",
    "ecr:ListImages",
    "ecr:BatchCheckLayerAvailability",
    "ecr:GetRepositoryPolicy",
    "ecr:GetLifecyclePolicy"
   ],
   "Resource": "*"
  }
 ]
}
```

2. After the policy is successfully created, it is time to create an IAM role in the account 

`aws iam create-role --role-name SnykECRRole --assume-role-policy-document file://assume.json` 

The `assume.json` file contains:


```
    {
    "Version": "2012-10-17",
    "Statement": [
    {
    "Effect": "Allow",
    "Principal": {
        "AWS": "arn:aws:iam::198361731867:user/ecr-integration-user"
    },
    "Action": "sts:AssumeRole"
        }
        ]
    }
```

3. Note the role ARN , it will be used in the next section

### Connecting Snyk with AWS 

1. Login to your [Snyk app](https://snyk.co/AWSMP-Workshop)
2. Click on `Settings` on top bar, click on `Integrations`
3. Select `ECR` and put in the region and IAM role ARN you created earlier. 

