---
layout: "docs"
page_title: "Aliyun - Secrets Engines"
sidebar_current: "docs-secrets-aliyun"
description: |-
  The Aliyun secrets engine for Vault generates access keys dynamically based on
  RAM policies.
---

# Aliyun Secrets Engine

The Aliyun secrets engine generates Aliyun access credentials dynamically based on RAM policies. This generally makes working with Aliyun RAM easier, since it does not involve clicking in the web UI. Additionally, the process is codified and mapped to internal auth methods . The Aliyun RAM credentials are time-based and are automatically revoked when the Vault lease expires.

## Setup

Most secrets engines must be configured in advance before they can perform their functions. These steps are usually completed by an operator or configuration management tool.

1. Enable the Aliyun secrets engine:

   ```bash
   $ vault secrets enable aliyun
   Success! Enabled the aliyun secrets engine at: aliyun/
   ```

   By default, the secrets engine will mount at the name of the engine. To enable the secrets engine at a different path, use the `-path` argument.

2. Configure the credentials that Vault uses to communicate with Aliyun to generate the RAM credentials:

   ```bash
   $ vault write aliyun/config/root \
       access_key=xxxxxxxxxxxxxxx \
       secret_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
       region=cn-hangzhou
   ```

   Internally, Vault will connect to Aliyun using these credentials. As such, these credentials must be a superset of any policies which might be granted on RAM credentials. Since Vault uses the official Aliyun SDK, it will use the specified credentials. You can also specify the credentials via the standard Aliyun environment credentials, shared file credentials, or RAM role/ECS task credentials.

   **Notice:** Even though the path above is `aliyun/config/root`, do not use your Aliyun root account credentials. Instead generate a dedicated user or role.

3. Configure a role that maps a name in Vault to a policy or policy file in Aliyun. When users generate credentials, they are generated against this role:

   ```bash
   $ vault write aliyun/roles/my-role \
       policy=-<<EOF
   {
     "Version": "1",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "ecs:*",
         "Resource": "*"
       }
     ]
   }
   EOF
   ```

   This creates a role named "my-role". When users generate credentials against this role, the resulting RAM credential will have the permissions specified in the policy provided as the argument.

   You can either supply a user inline policy or provide a reference to an existing Aliyun policy's type and name:

   ```bash
   $ vault write aliyun/roles/my-role \
   	policy_type=Custom
   ```

   For more information on RAM policies, please see the [Aliyun RAM policy documentation](https://help.aliyun.com/document_detail/28651.html).

## Usage

After the secrets engine is configured and a user/machine has a Vault token with the proper permission, it can generate credentials.

1. Generate a new credential by reading from the `/creds` endpoint with the name of the role:

   ```bash
   $ vault read aliyun/creds/my-role
   Key                Value
   ---                -----
   lease_id           aliyun/creds/my-role/f3e92392-7d9c-09c8-c921-575d62fe80d8
   lease_duration     768h
   lease_renewable    true
   access_key         xxxxxxxxxxxxxxxxxxx
   secret_key         xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   security_token     <nil>
   ```

   Each invocation of the command will generate a new credential.

   Unfortunately, RAM credentials are eventually consistent with respect to other Aliyun services. If you are planning on using these credential in a pipeline, you may need to add a delay of 5-10 seconds (or more) after fetching credentials before they can be used successfully.

   If you want to be able to use credentials without the wait, consider using the STS method of fetching keys. RAM credentials supported by an STS token are available for use as soon as they are generated.

## Policy for Vault

The `aliyun/config/root` credentials need permission to manage dynamic RAM users. Here is an example Aliyun RAM policy that grants the most commonly required permissions Vault needs:

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ram:CreatePolicy",
        "ram:AttachPolicyToUser",
        "ram:CreateAccessKey",
        "ram:CreateUser",
        "ram:DeleteAccessKey",
        "ram:DeleteUser",
        "ram:DetachPolicyFromUser",
        "ram:ListAccessKeys",
        "ram:ListGroupsForUser",
        "ram:ListPoliciesForUser",
        "ram:RemoveUserFromGroup"
      ],
      "Resource": [
        "acs:ram:*:${AccountId}:user/*",
        "acs:ram:*:${AccountId}:policy/*"
      ]
    }
  ]
}
```

## STS credentials

Vault also supports an STS credentials instead of creating a new RAM user.

Vault supports [STS AssumeRole](https://help.aliyun.com/document_detail/28763.html).

### STS AssumeRole

STS AssumeRole is typically used for cross-account authentication or single sign-on (SSO) scenarios. AssumeRole need to prepare:

1. The ARN of a RAM role to assume
2. RAM inline policies and/or managed policies attached to the RAM role
3. RAM trust policy attached to the RAM role to grant privileges for one identity to assume the role.

AssumeRole adds a few benefits:

1. Assumed roles can invoke RAM and STS operations, if granted by the role's RAM policies.
2. Assumed roles support cross-account authentication

The `aliyun/config/root` credentials must have an RAM policy that allows `sts:AssumeRole` against the target role:

```json
{
  "Version": "1",
  "Statement": {
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "acs:ram:*:${AccountId}:role/*"
  }
}
```

You must attach a trust policy to the target RAM role to assume, allowing the aliyun/root/config credentials to assume the role.

```json
{
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {
        "RAM": [
          "acs:ram::${AccountId}:root"
        ]
      }
    }
  ],
  "Version": "1"
}
```

Finally, let's create a "deploy" policy using the arn of our role to assume:

```Bash
$ vault write aliyun/roles/deploy \
    policy=acs:ram::${AccountId}:role/RoleNameToAssume
```

To generate a new set of STS assumed role credentials, we again write to the role using the aliyun/sts endpoint:

```Bash
$vault write aliyun/sts/deploy ttl=60m
Key                Value
---                -----
lease_id           aliyun/sts/deploy/337ed8d8-56c3-af8b-3abf-9a7a3732c454
lease_duration     59m59s
lease_renewable    false
access_key         STS.NHeQqqCD4KVGcExVgXqd2w1sh
secret_key         3XKBFKmwtK7T8HFue3g3U1ELidq3BeG3YiY2Q4MFVsjW
security_token     CAIS/QF1q6Ft5B2yfSjIr4vQGsvFrpsV/JSsYWPJsmcNfesemPTYijz2IHBJfXlhAu8avv00nW9Y5/4ZlrxtQoJBWQmdMJArscQPqVnxJtWa6pztNXroBSThSwapEBfe8JL4QYeQFaHwGJqEb1TDiVUAo9/TfimjWFqIKICAjYUdAP0cQgi/a0gtZr4UXHwAzvUXLnzML/2gHwf3i27LdipStxF7lHl05NbUoKTeyGKH0gankbZN/9mueML9PpkxBvolDYfpht4RX7HazStd5yJN8KpLl6Fe8V/FxIrNXgABsk7Zb7qNqYQwfF4hPbJbB6NfsOb1iPlkqmVlRDR7So0nGoABd2Ep/4P07GGUxB4THMV3rD9E/N7ZTucS+4ylOtBKI6Zblg1Je63IpiMsZWdbReSYgl+YFGaZdsF3EuD9tervvddics189wK/hgbbD0Jw3f/gyazKbfa7mHCJWfwullhZi0aTHtwQ6eSTsT3nGdc28h1CFcunXIab18pxk0ph1O8=
```

## Troubleshooting

### Dynamic RAM user errors

If you get an error message similar to either of the following, the root credentials that you wrote to `aliyun/config/root` have insufficient privilege:

```Bash
$ vault read aliyun/creds/my-role
Error reading aliyun/creds/my-role: Error making API request.

URL: GET http://127.0.0.1:8200/v1/aliyun/creds/my-role
Code: 400. Errors:

* Error creating RAM user: SDK.ServerError
ErrorCode: NoPermissions
Recommend: 
RequestId: CC4B2800-F4E0-4D85-8BF2-915F76798418
Message: You are not authorized to do this action. Resource: acs:ram:*:000000000000:user/* Action: ram:CreateUser
```

If you get stuck at any time, simply run `vault path-help aliyun` or with a subpath for interactive help output.

## API

The Aliyun secrets engine has a full HTTP API. Please see the Aliyun secrets engine API for more details.