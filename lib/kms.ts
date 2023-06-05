import {Construct} from "constructs";
import * as cdk from "aws-cdk-lib";
import * as kms from "aws-cdk-lib/aws-kms";
import * as iam from "aws-cdk-lib/aws-iam";
import {StackProps} from "aws-cdk-lib";

export interface RDSKMSKeyProps extends StackProps {
    appName: string;
    envName: string;
    kmsDescription: string;
    keyName: string;
}

export default class KMSConstruct extends Construct {
    constructor(scope: Construct, props: RDSKMSKeyProps) {
        super(scope, `${props.appName}-${props.envName}-kms`);

        const policyDocument = new iam.PolicyDocument({
            statements: [
                new iam.PolicyStatement({
                    sid: "Enable IAM User Permissions",
                    effect: iam.Effect.ALLOW,
                    principals: [new iam.AccountRootPrincipal()],
                    actions: ["kms:*"],
                    resources: ["*"],
                }),
                new iam.PolicyStatement({
                    sid: "Allow access for Key Administrators",
                    effect: iam.Effect.ALLOW,
                    principals: [new iam.AccountRootPrincipal()],
                    actions: ["kms:*"],
                    resources: ["*"],
                }),
                new iam.PolicyStatement({
                    sid: "Allow use of the key",
                    effect: iam.Effect.ALLOW,
                    principals: [new iam.AccountRootPrincipal()],
                    actions: [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:DescribeKey",
                    ],
                    resources: ["*"],
                }),
                new iam.PolicyStatement({
                    sid: "Allow attachment of persistent resources",
                    effect: iam.Effect.ALLOW,
                    principals: [new iam.AccountRootPrincipal()],
                    actions: ["kms:CreateGrant", "kms:ListGrants", "kms:RevokeGrant"],
                    resources: ["*"],
                    conditions: {
                        Bool: {"kms:GrantIsForAWSResource": true},
                    },
                }),
            ],
        });

        new kms.Key(this, props.keyName, {
            alias: props.keyName,
            description: props.kmsDescription,
            removalPolicy: cdk.RemovalPolicy.DESTROY,
            policy: policyDocument,
        });
    }
}
