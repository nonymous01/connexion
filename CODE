import os
import sys
import json
import pathlib
from datetime import datetime
from pathlib import Path
BASE_PATH = pathlib.Path(__file__).resolve()
sys.path.append(f"{BASE_PATH.parents[0]}")
import boto3
from aws_cdk import (
    Stack,
    Size,
    Duration,
    RemovalPolicy,
)
import aws_cdk as core
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_apigateway as apigateway
from aws_cdk.aws_apigateway import IdentitySource, MethodResponse
from aws_cdk import aws_logs as logs
from aws_cdk.aws_logs import LogGroup
from aws_cdk import aws_logs_destinations as destinations
from aws_cdk import aws_dynamodb as ddb
from aws_cdk import aws_events as events
from aws_cdk import aws_s3 as s3
from constructs import Construct
from stack_constructs.lambda_function import LambdaFunction
from stack_constructs.dynamodb import DynamoDB
from stack_constructs.lambda_layer import LambdaLayer


class CdkAwsStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        env = self.node.try_get_context("env")
        self.context = self.node.try_get_context(env)

        # block to add iam pass role permissions for all mlops deployment roles deployment accounts in the region
        env_tokens = env.split("_")
        deployment_env = env_tokens[1]
        print(f"*************************:::{env=}")
        print(f"*************************:::{deployment_env=}")
        region = self.context["region"]
        assume_role_resources = []

        #aws_api_gateway_stage = self.context["aws_api_gateway_stage"]

        aws_account_number = self.context["aws_account_number"]

        aws_account_number_other_region = self.context[
            "aws_account_number_other_region"
        ]
        automation_role_name_other_region = self.context[
            "lambda_automation_role_name_other_region"
        ]

        automation_role_name = self.context['lambda_automation_role_name']

        self.prefix_id = "aws-mlops"
        self.mlops_automation_role = f"arn:aws:iam::{aws_account_number}:role/{automation_role_name}"

        deployment_execution_role_suffix = "*_MLOPS_EXECUTION*"
        deployment_role_suffix = "*_MLOPS_DEPLOYMENT*"
        deployment_ops_role_suffix = "*_MLOPS_OPERATIONS"


        ######### Define Common IAM Policies ################
        assume_role_resources.extend([
            f"arn:aws:iam::{aws_account_number_other_region}:role/{automation_role_name_other_region}",
            f"arn:aws:iam::{aws_account_number}:role/{automation_role_name}",
            f"arn:aws:iam::*:role/{deployment_execution_role_suffix}",
            f"arn:aws:iam::*:role/{deployment_role_suffix}",
            f"arn:aws:iam::*:role/{deployment_ops_role_suffix}",
        ])

        print(f"*************************:::{assume_role_resources=}")
        policy_statement_assume_role = iam.PolicyStatement(
            sid="assumerole",
            effect=iam.Effect.ALLOW,
            actions=["sts:AssumeRole"],
            resources=assume_role_resources,
        )
        
        policy_statement_pass_role = iam.PolicyStatement(
            sid="passrole",
            effect=iam.Effect.ALLOW,
            actions=["iam:PassRole"],
            resources=[f"arn:aws:iam::{aws_account_number}:role/{automation_role_name}"],
        )

        policy_statement_lambda = iam.PolicyStatement(
            sid="lambda",
            effect=iam.Effect.ALLOW,
            actions=["lambda:InvokeAsync", "lambda:InvokeFunction"],
            resources=[
                f"arn:aws:lambda:*:{aws_account_number}:function:*"
            ],
        )

        policy_statement_kms = iam.PolicyStatement(
            sid="kms",
            effect=iam.Effect.ALLOW,
            actions=[
                "kms:Get*",
                "kms:Decrypt",
                "kms:List*",
                "kms:ReEncryptFrom",
                "kms:Encrypt",
                "kms:ReEncryptTo",
                "kms:Describe",
                "kms:GenerateDataKey",
                "kms:GetKeyPolicy",
            ],
            resources=[f"arn:aws:kms:{region}:{aws_account_number}:*/*"],
        )

        policy_statement_secrets = iam.PolicyStatement(
            sid="SecretsManager",
            effect=iam.Effect.ALLOW,
            actions=["secretsmanager:*"],
            resources=[
                f"arn:aws:secretsmanager:{region}:{aws_account_number}:secret:*"
            ],
        )

        policy_statement_logs = iam.PolicyStatement(
            sid="logs1",
            effect=iam.Effect.ALLOW,
            actions=[
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents",
                "logs:GetLogEvents",
                "logs:FilterLogEvents",
                "logs:Describe*",
                "logs:Get*",
                "logs:List*",
                "logs:StartQuery",
                "logs:GetQueryResults"
            ],
            resources=[f"arn:aws:logs:{region}:{aws_account_number}:*:*",
                       f"arn:aws:logs:{region}:{aws_account_number}:*:*:*",
                       f"arn:aws:logs:{region}:{aws_account_number}:*:*:*:*"
                       ],
        )

        policy_statement_api = iam.PolicyStatement(
            sid="APIGateway",
            effect=iam.Effect.ALLOW,
            actions=["apigateway:GET"],
            resources=["*"],
        )

        aws_s3_bucket_name = self.context["aws_s3_bucket_name"]
        policy_statement_s3 = iam.PolicyStatement(
            sid="S3",
            effect=iam.Effect.ALLOW,
            actions=[
                "s3:RestoreObject",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:AbortMultipartUpload",
                "s3:CreateMultipartUpload",
                "s3:List*",
                "s3:Create*",
                "s3:Get*",
                "s3:Put*",
            ],
            resources=[
                f"arn:aws:s3:::{aws_s3_bucket_name}/applications/*",
                f"arn:aws:s3:::{aws_s3_bucket_name}/.archival/*",
                f"arn:aws:s3:::{aws_s3_bucket_name}",
                f"arn:aws:s3:::app01*"
            ],
        )

        policy_statement_ec2 = iam.PolicyStatement(
            sid="ec2",
            effect=iam.Effect.ALLOW,
            actions=[
                "ec2:CreateNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DeleteNetworkInterface",
                "ec2:AssignPrivateIpAddresses",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcs",
                "ec2:UnassignPrivateIpAddresses",
                "ec2:*VpcEndpoint*",
            ],
            resources=["*"],
        )

        policy_statement_email = iam.PolicyStatement(
            sid="SendEmailSES",
            effect=iam.Effect.ALLOW,
            actions=[
                "ses:SendEmail",
            ],
            resources=[f"arn:aws:ses:{region}:{aws_account_number}:*/*"],
        )

        policy_statement_dynamodb = iam.PolicyStatement(
            sid="DynamoDB",
            effect=iam.Effect.ALLOW,
            actions=[
                "dynamodb:List*",
                "dynamodb:DescribeReservedCapacity*",
                "dynamodb:DescribeLimits",
                "dynamodb:DescribeTimeToLive",
                "dynamodb:BatchGet*",
                "dynamodb:DescribeStream",
                "dynamodb:DescribeTable",
                "dynamodb:Get*",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchWrite*",
                "dynamodb:CreateTable",
                "dynamodb:Delete*",
                "dynamodb:Update*",
                "dynamodb:PutItem"
            ],
            resources=[f"arn:aws:dynamodb:{region}:{aws_account_number}:*/*"],
        )

        policy_statement_sagemaker = iam.PolicyStatement(
            sid="Sagemaker",
            effect=iam.Effect.ALLOW,
            actions=[
                "sagemaker:*",
            ],
            resources=[f"arn:aws:sagemaker:{region}:{aws_account_number}:*/*"],
        )
        
        policy_statement_stepfunctions = iam.PolicyStatement(
            sid="Stepfunctions",
            effect=iam.Effect.ALLOW,
            actions=[
                "states:StartExecution",
            ],
            resources=[
                f"arn:aws:states:{region}:{aws_account_number}:stateMachine:*"
            ],
        )

        ######### MLOps automation role ################

        # Create MLops automation role
        aws_iam_permission_boundary = self.context["aws_iam_permission_boundary"]
        permissions_boundary = iam.ManagedPolicy.from_managed_policy_arn(
            self, "Boundary2", aws_iam_permission_boundary
        )
        
        lambda_automation_role = iam.Role(
            self,
            "AutomationRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("apigateway.amazonaws.com"),
                iam.ServicePrincipal("states.amazonaws.com"),
                iam.ServicePrincipal("lambda.amazonaws.com"),
                iam.AccountPrincipal(aws_account_number_other_region),
                iam.AccountPrincipal(aws_account_number),
            ),
            description="Credentials Lambda role",
            role_name=automation_role_name,
            permissions_boundary=permissions_boundary,
        )

        # Create Mlops policy
        mlops_automation_policy_name = self.context["lambda_automation_policy_name"]

        mlops_automation_policy_doc = iam.PolicyDocument()
        mlops_automation_policy_doc.add_statements(policy_statement_pass_role)
        mlops_automation_policy_doc.add_statements(policy_statement_assume_role)
        mlops_automation_policy_doc.add_statements(policy_statement_lambda)
        mlops_automation_policy_doc.add_statements(policy_statement_ec2)
        mlops_automation_policy_doc.add_statements(policy_statement_logs)
        mlops_automation_policy_doc.add_statements(policy_statement_kms)
        mlops_automation_policy_doc.add_statements(policy_statement_s3)
        mlops_automation_policy_doc.add_statements(policy_statement_secrets)
        mlops_automation_policy_doc.add_statements(policy_statement_api)
        mlops_automation_policy_doc.add_statements(policy_statement_email)
        mlops_automation_policy_doc.add_statements(policy_statement_dynamodb)
        mlops_automation_policy_doc.add_statements(policy_statement_sagemaker)
        mlops_automation_policy_doc.add_statements(policy_statement_stepfunctions)

        mlops_automation_policy = iam.Policy(
            self,
            "MLOPSPolicyAutomation",
            policy_name=mlops_automation_policy_name,
            document=mlops_automation_policy_doc,
        )

        mlops_automation_policy.attach_to_role(lambda_automation_role)

        lambda_automation_role.add_managed_policy(
            iam.ManagedPolicy.from_managed_policy_arn(
                scope=self,
                id="AWSLambdaVPCAccessExecutionRole",
                managed_policy_arn="arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
            )
        )

        # Network configurations for Lambdas and API Gateways

        v_aws_vpc_name = self.context["aws_vpc_name"]
        v_aws_vpc_subnet_1 = self.context["aws_vpc_subnet_1"]
        v_aws_vpc_subnet_2 = self.context["aws_vpc_subnet_2"]
        v_aws_security_group_default = self.context["aws_security_group_default"]
        v_aws_security_dns_servers = self.context["aws_security_dns_servers"]        

        aws_vpc_endpoint_api_gateway_id = self.context[
            "aws_vpc_endpoint_api_gateway_id"
        ]

        vpc = ec2.Vpc.from_vpc_attributes(
            self,
            "vpc",
            vpc_id=v_aws_vpc_name,
            availability_zones=[region],
            private_subnet_ids=[v_aws_vpc_subnet_1, v_aws_vpc_subnet_2],
        )
        security_group_ec2_1 = ec2.SecurityGroup.from_security_group_id(
            self, "security1", v_aws_security_group_default, mutable=False, allow_all_outbound=False
        )
        security_group_ec2_2 = ec2.SecurityGroup.from_security_group_id(
            self, "security2", v_aws_security_dns_servers, mutable=False, allow_all_outbound=False
        )

        aws_vpc_endpoint_api_gateway = (
            ec2.InterfaceVpcEndpoint.from_interface_vpc_endpoint_attributes(
                self,
                id="vpc-endpoint",
                port=443,
                vpc_endpoint_id=aws_vpc_endpoint_api_gateway_id,
            )
        )

        # ==================================================
        # =============== LAMBDA LAYERS ====================
        # ==================================================
        self.prefix_id = "aws-mlops"
        self.lambdas_directory = "../../python_scripts/automation_account_lambdas/"


        def read_requirements(file_name):
            # get the absolute path to the file (script) being executed
            current_path = Path(__file__).resolve()

            # get the parent directory (two levels up)
            requirements_path = current_path.parents[1] / "requirements" / file_name

            with open(requirements_path, 'r') as file:
                return ' '.join([line.strip() for line in file])

        self.common_requirements = read_requirements('common_requirements.txt')
        self.token_requirements = read_requirements('token_requirements.txt')
        self.mlflow_requirements = read_requirements('mlflow_requirements.txt')
        self.model_promotion_requirements = read_requirements('model_promotion_requirements.txt')

        s3_bucket_layer = s3.Bucket(
            self,
            f"{self.prefix_id}_s3_bucket_layer",
            auto_delete_objects=False
        )

        lambda_layer = LambdaLayer(
            scope=self,
            id=f"{self.prefix_id}_lambda_layer",
            s3_bucket=s3_bucket_layer.bucket_name,
            role=lambda_automation_role.role_name,
        )

        mlops_common_requirements_layer = lambda_layer.build(
            layer_name="mlops_common_libraries",
            code_dir=f"{self.lambdas_directory}/lambda_layer_requirements",
            vpc=vpc,
            security_groups=[security_group_ec2_1, security_group_ec2_2],
            environments={
                "REQUIREMENTS": self.common_requirements,
                "S3_BUCKET": s3_bucket_layer.bucket_name,
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"]
            },
            runtime = lambda_.Runtime.PYTHON_3_8
        )

        mlops_token_requirements_layer = lambda_layer.build(
            layer_name="mlops_token_libraries",
            code_dir=f"{self.lambdas_directory}/lambda_layer_requirements",
            vpc=vpc,
            security_groups=[security_group_ec2_1, security_group_ec2_2],
            environments={
                "REQUIREMENTS": self.token_requirements,
                "S3_BUCKET": s3_bucket_layer.bucket_name,
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"]
            },
            runtime=lambda_.Runtime.PYTHON_3_8
        )
        
        mlops_mlflow_libraries = lambda_layer.build(
            layer_name="mlops_mlflow_libraries",
            code_dir=f"{self.lambdas_directory}/lambda_layer_requirements",
            vpc=vpc,
            security_groups=[security_group_ec2_1, security_group_ec2_2],
            environments={
                "REQUIREMENTS": self.mlflow_requirements,
                "S3_BUCKET": s3_bucket_layer.bucket_name,
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"]
            }
        )
        model_promotion_libraries = lambda_layer.build(
            layer_name="model_promotion_libraries",
            code_dir=f"{self.lambdas_directory}/lambda_layer_requirements",
            vpc=vpc,
            security_groups=[security_group_ec2_1, security_group_ec2_2],
            environments={
                "REQUIREMENTS": self.model_promotion_requirements,
                "S3_BUCKET": s3_bucket_layer.bucket_name,
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"]
            }
        )

        self.automation_lambda_code_dir = os.path.join("../../python_scripts/automation_account_lambdas/")

        # Initialize Lambda Construct

        LambdaBuilder = LambdaFunction(
            scope=self,
            id="automation-lambda",
            role=lambda_automation_role,
            vpc=vpc,
            security_groups=[security_group_ec2_1, security_group_ec2_2],
        )

        deployment_accounts = self.context["deployment_account_numbers"]
        ######### Lambda Authorizers #########
        # Lambda Authorizer 1
        automation_authorizer_lambda = LambdaBuilder.build(
            function_name="lambda_authorizer",
            code_dir=os.path.join("../../python_scripts/automation_account_lambdas/"),
            handler="lambda_authorizer_function.lambda_handler",
            runtime=lambda_.Runtime.PYTHON_3_8,
            memory_size=128,
            timeout=Duration.minutes(10),
            layers=[mlops_common_requirements_layer, mlops_token_requirements_layer],
            environment={
                "region": self.context["region"],
                "AWS_STS_REGIONAL_ENDPOINTS": "regional",
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"],
            },
            provisioned_concurrent_executions=2,
        )

        LambdaFunction.add_cross_account_permissions(
            function_name="lambda_authorizer",
            region=self.context["region"],
            permission_accounts=deployment_accounts,
            lambda_function=automation_authorizer_lambda
        )

        # Lambda Authorizer 2
        deployment_authorizer_lambda = LambdaBuilder.build(
            function_name="deployment_lambda_authorizer",
            code_dir=os.path.join("../../python_scripts/automation_account_lambdas/"),
            handler="deployment_lambda_authorizer_function.lambda_handler",
            runtime=lambda_.Runtime.PYTHON_3_8,
            memory_size=128,
            timeout=Duration.minutes(10),
            layers=[mlops_common_requirements_layer, mlops_token_requirements_layer],
            environment={
                "region": self.context["region"],
                "AWS_STS_REGIONAL_ENDPOINTS": "regional",
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"],
                "PLATFORM_AUTOMATION_ENV": deployment_env,
            },
            provisioned_concurrent_executions=2,
        )


        LambdaFunction.add_cross_account_permissions(
            function_name="deployment_lambda_authorizer",
            region=self.context["region"],
            permission_accounts=deployment_accounts,
            lambda_function=deployment_authorizer_lambda
        )

        ######### Lambda Credentials #########
        credentials_lambda = LambdaBuilder.build(
            function_name="aws-mlops-credentials-generation",
            code_dir = os.path.join("../../python_scripts/automation_account_lambdas/"),
            handler="credentials_generation_function.lambda_handler",
            runtime=lambda_.Runtime.PYTHON_3_9,
            timeout=Duration.minutes(15),
            layers=[mlops_common_requirements_layer],
            environment={
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"],
            },
            provisioned_concurrent_executions=2,
        )


        ######### Lambda MLOps Pipelines #########

        aws_lambda_pipelines = LambdaBuilder.build(
            function_name="aws-mlops-pipelines",
            code_dir = os.path.join("../../python_scripts/automation_account_lambdas/"),
            handler="pipeline_deployment_function.lambda_handler",
            runtime=lambda_.Runtime.PYTHON_3_9,
            timeout=Duration.minutes(15),
            layers=[mlops_common_requirements_layer],
            environment={
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"],
            },
            provisioned_concurrent_executions=2,
        )


        ######### Lambda MLOps Model Endpoints #########
        ecr_repository_name = "f1ai/platform/mlops_model_deployment"
        image_tag = "latest"
        memory = 10240

        ecr_repository = ecr.Repository.from_repository_name(
            scope=self,
            id="repository",
            repository_name=ecr_repository_name,
        )

        ecr_image = lambda_.DockerImageCode.from_ecr(
            repository=ecr_repository, tag=image_tag
        )

        aws_lambda_model_endpoint_base = lambda_.DockerImageFunction(
            scope=self,
            id="aws-mlops-model-endpoints",
            function_name="aws-mlops-model-endpoints",
            code=ecr_image,
            memory_size=memory,
            ephemeral_storage_size=Size.mebibytes(memory),
            role=lambda_automation_role,
            vpc=vpc,
            security_groups=[security_group_ec2_1,security_group_ec2_2],
            timeout=Duration.minutes(15),
            environment={
                "DATABRICKS_HOST": self.context["databricks_host"],
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"],
              	"test": datetime.now().strftime("%Y%m%d%H%M%S")
            },
        )

        # Moved the async configuration at alias level. 
        # aws_lambda_model_endpoint_base.configure_async_invoke(retry_attempts=0)

        aws_lambda_model_endpoint = lambda_.Alias(self, "aws-mlops-model-endpoints-alias",
            alias_name="live",
            version=aws_lambda_model_endpoint_base.current_version,
            provisioned_concurrent_executions=2
        )

        aws_lambda_model_endpoint.configure_async_invoke(retry_attempts=0)

        ##### Lambda MLOps Service Endpoints ####

        aws_lambda_service_endpoint = LambdaBuilder.build(
            function_name="aws-mlops-service-endpoints",
            code_dir = os.path.join("../../python_scripts/automation_account_lambdas/"),
            handler="service_endpoint_deployment_function.lambda_handler",
            runtime=lambda_.Runtime.PYTHON_3_9,
            timeout=Duration.minutes(15),
            environment={
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"],
            },
            provisioned_concurrent_executions=2,
        )


        ##### Lambda MLOps Models ####

        aws_lambda_models = LambdaBuilder.build(
            function_name="aws-mlops-models",
            code_dir = os.path.join("../../python_scripts/automation_account_lambdas/"),
            handler="model_function.lambda_handler",
            runtime=lambda_.Runtime.PYTHON_3_10,
            timeout=Duration.minutes(15),
            layers=[model_promotion_libraries],
            environment={
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"],
            },
            provisioned_concurrent_executions=0,
        )

        ##### Lambda MLOps Authorizer ####

        authorizer_mlops = apigateway.TokenAuthorizer(
            self,
            "AuthLambdaAuthorizerMLOps",
            authorizer_name="lambda_authorizer",
            handler=automation_authorizer_lambda,
            identity_source=IdentitySource.header("token"),
            results_cache_ttl=core.Duration.minutes(5) # Enable caching for 5 minutes
        )


    ##### MLOps Automation API ####

        # Resource Policy for API Gateway
        statement = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["execute-api:Invoke"],
            principals=[iam.AnyPrincipal()],
            resources=[f"arn:aws:execute-api:{region}:{aws_account_number}:*/*/*/*"],
        )
        policy = iam.PolicyDocument()
        policy.add_statements(statement)


        method_responses = [
            MethodResponse(status_code="200"),
            MethodResponse(status_code="400"),
        ]

        integration_response1 = apigateway.IntegrationResponse(
            status_code="200", response_templates={"application/json": ""}
        )
        integration_response2 = apigateway.IntegrationResponse(
            status_code="400", response_templates={"application/json": ""}
        )     



        # API Gateway
        api = apigateway.RestApi(
            self,
            id="rest-api",
            rest_api_name="mlops_automation",
            description="API Description",
            cloud_watch_role=False,
            endpoint_configuration=apigateway.EndpointConfiguration(
                types=[apigateway.EndpointType.PRIVATE],
                vpc_endpoints=[aws_vpc_endpoint_api_gateway],
            ),
            deploy_options=apigateway.StageOptions(
                stage_name="mlops",
                #logging_level=apigateway.MethodLoggingLevel.INFO,
                #data_trace_enabled=True,
            ),
            policy=policy
        )        

        ##### Endpoints #####
        aws_resources_mlops_endpoints = api.root.add_resource("model_endpoints")

        # Create
        aws_resources_mlops_model_inference_create = (
            aws_resources_mlops_endpoints.add_resource("create")
        )
        int_json = """##  See http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html
            ##  This template will pass through all parameters including path, querystring, header, stage variables, and context through to the integration endpoint via the body/payload
            #set($allParams = $input.params())
            {
            "body-json" : $input.json('$'),
            "params" : {
            #foreach($type in $allParams.keySet())
                #set($params = $allParams.get($type))
            "$type" : {
                #foreach($paramName in $params.keySet())
                "$paramName" : "$util.escapeJavaScript($params.get($paramName))"
                    #if($foreach.hasNext),#end
                #end
            }
                #if($foreach.hasNext),#end
            #end
            },
            "stage-variables" : {
            #foreach($key in $stageVariables.keySet())
            "$key" : "$util.escapeJavaScript($stageVariables.get($key))"
                #if($foreach.hasNext),#end
            #end
            },
            "context" : {
                "account-id" : "$context.identity.accountId",
                "api-id" : "$context.apiId",
                "api-key" : "$context.identity.apiKey",
                "authorizer-principal-id" : "$context.authorizer.principalId",
                "caller" : "$context.identity.caller",
                "http-method" : "$context.httpMethod",
                "stage" : "$context.stage",
                "source-ip" : "$context.identity.sourceIp",
                "user" : "$context.identity.user",
                "user-agent" : "$context.identity.userAgent",
                "user-arn" : "$context.identity.userArn",
                "request-id" : "$context.requestId",
                "resource-id" : "$context.resourceId",
                "resource-path" : "$context.resourcePath",
                "requestContext": {"authorizer" : {
                    #foreach($key in $context.authorizer.keySet())
                    "$key" : "$context.authorizer.get($key)"
                        #if($foreach.hasNext),#end
                    #end
                    }}
                }
            }"""

        aws_resources_mlops_model_inference_create.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_model_endpoint,
                proxy=False,
                request_parameters={
                    "integration.request.header.X-Amz-Invocation-Type": "'Event'"
                },
                request_templates={"application/json": int_json},
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Describe
        aws_resources_mlops_model_inference_describe = (
            aws_resources_mlops_endpoints.add_resource("describe")
        )
        aws_resources_mlops_model_inference_describe.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_model_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )
        # List
        aws_resources_mlops_model_inference_list = (
            aws_resources_mlops_endpoints.add_resource("list")
        )
        aws_resources_mlops_model_inference_list.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_model_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Delete
        aws_resources_mlops_model_inference_delete = (
            aws_resources_mlops_endpoints.add_resource("delete")
        )
        aws_resources_mlops_model_inference_delete.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_model_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # list_log_streams
        aws_resources_mlops_model_list_log_streams = (
            aws_resources_mlops_endpoints.add_resource("list_log_streams")
        )
        aws_resources_mlops_model_list_log_streams.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_model_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # get_log_stream
        aws_resources_mlops_model_get_log_stream = (
            aws_resources_mlops_endpoints.add_resource("get_log_stream")
        )
        aws_resources_mlops_model_get_log_stream.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_model_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )
        
        # filter_log_stream
        aws_resources_mlops_model_get_log_stream = (
            aws_resources_mlops_endpoints.add_resource("filter_log_stream")
        )
        aws_resources_mlops_model_get_log_stream.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_model_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # put_autoscaling
        aws_resources_mlops_model_put_autoscaling = (
            aws_resources_mlops_endpoints.add_resource("put_autoscaling")
        )
        aws_resources_mlops_model_put_autoscaling.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_model_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # update_weights
        aws_resources_mlops_model_update_weights = (
            aws_resources_mlops_endpoints.add_resource("update_weights")
        )
        aws_resources_mlops_model_update_weights.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_model_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # update_instance_count
        aws_resources_mlops_model_update_instance_count = (
            aws_resources_mlops_endpoints.add_resource("update_instance_count")
        )
        aws_resources_mlops_model_update_instance_count.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_model_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        ##### Pipelines #####
        aws_resources_mlops_pipelines = api.root.add_resource("pipelines")

        # Create
        aws_resources_mlops_pipelines_create = (
            aws_resources_mlops_pipelines.add_resource("create")
        )
        aws_resources_mlops_pipelines_create.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Start
        aws_resources_mlops_pipelines_start = (
            aws_resources_mlops_pipelines.add_resource("start")
        )
        aws_resources_mlops_pipelines_start.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Stop
        aws_resources_mlops_pipelines_stop = aws_resources_mlops_pipelines.add_resource(
            "stop"
        )
        aws_resources_mlops_pipelines_stop.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Describe
        aws_resources_mlops_pipelines_describe = (
            aws_resources_mlops_pipelines.add_resource("describe")
        )
        aws_resources_mlops_pipelines_describe.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # List
        aws_resources_mlops_pipelines_list = aws_resources_mlops_pipelines.add_resource(
            "list"
        )
        aws_resources_mlops_pipelines_list.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Delete
        aws_resources_mlops_pipelines_delete = (
            aws_resources_mlops_pipelines.add_resource("delete")
        )
        aws_resources_mlops_pipelines_delete.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Set schedule
        aws_resources_mlops_pipelines_set_schedule = (
            aws_resources_mlops_pipelines.add_resource("set_schedule")
        )
        aws_resources_mlops_pipelines_set_schedule.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Delete schedule
        aws_resources_mlops_pipelines_delete_schedule = (
            aws_resources_mlops_pipelines.add_resource("delete_schedule")
        )
        aws_resources_mlops_pipelines_delete_schedule.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Subcribe topic
        aws_resources_mlops_pipelines_subscribe = aws_resources_mlops_pipelines.add_resource('subscribe')
        aws_resources_mlops_pipelines_subscribe.add_method(
            'POST',
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Unsubcribe topic
        aws_resources_mlops_pipelines_unsubscribe = aws_resources_mlops_pipelines.add_resource('unsubscribe')
        aws_resources_mlops_pipelines_unsubscribe.add_method(
            'POST',
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # List topic subscriptions
        aws_resources_mlops_pipelines_list_notifications = aws_resources_mlops_pipelines.add_resource('list_notifications')
        aws_resources_mlops_pipelines_list_notifications.add_method(
            'POST',
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

         # Describe pipeline
        aws_resources_mlops_pipelines_describe_pipeline = aws_resources_mlops_pipelines.add_resource('describe_pipeline')
        aws_resources_mlops_pipelines_describe_pipeline.add_method(
            'POST',
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1,integration_response2]
                ),
            method_responses=method_responses
        )

        # Describe pipeline execution
        aws_resources_mlops_pipelines_describe_pipeline_execution = aws_resources_mlops_pipelines.add_resource('describe_pipeline_execution')
        aws_resources_mlops_pipelines_describe_pipeline_execution.add_method(
            'POST',
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1,integration_response2]
                ),
            method_responses=method_responses
        )

        # List pipeline executions
        aws_resources_mlops_pipelines_list_pipeline_executions = aws_resources_mlops_pipelines.add_resource('list_pipeline_executions')
        aws_resources_mlops_pipelines_list_pipeline_executions.add_method(
            'POST',
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1,integration_response2]
                ),
            method_responses=method_responses
        )

        # List log streams
        aws_resources_mlops_pipelines_list_pipeline_step_log_streams = aws_resources_mlops_pipelines.add_resource('list_pipeline_step_log_streams')
        aws_resources_mlops_pipelines_list_pipeline_step_log_streams.add_method(
            'POST',
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1,integration_response2]
                ),
            method_responses=method_responses
        )

        # Describe log stream
        aws_resources_mlops_pipelines_get_pipeline_step_log_stream = aws_resources_mlops_pipelines.add_resource('get_pipeline_step_log_stream')
        aws_resources_mlops_pipelines_get_pipeline_step_log_stream.add_method(
            'POST',
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1,integration_response2]
                ),
            method_responses=method_responses
        )

        ##### Service Endpoints #####
        aws_resources_mlops_service_endpoint = api.root.add_resource(
            "service_endpoints"
        )

        # Create
        aws_resources_mlops_service_endpoint_create = (
            aws_resources_mlops_service_endpoint.add_resource("create")
        )
        aws_resources_mlops_service_endpoint_create.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_service_endpoint,
                proxy=False,
                request_parameters={
                    "integration.request.header.X-Amz-Invocation-Type": "'Event'"
                },
                request_templates={"application/json": int_json},
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Describe
        aws_resources_mlops_service_endpoint_describe = (
            aws_resources_mlops_service_endpoint.add_resource("describe")
        )
        aws_resources_mlops_service_endpoint_describe.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_service_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )
        # List
        aws_resources_mlops_service_endpoint_list = (
            aws_resources_mlops_service_endpoint.add_resource("list")
        )
        aws_resources_mlops_service_endpoint_list.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_service_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Delete
        aws_resources_mlops_service_endpoint_delete = (
            aws_resources_mlops_service_endpoint.add_resource("delete")
        )
        aws_resources_mlops_service_endpoint_delete.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_service_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # list_log_streams
        aws_resources_mlops_service_list_log_streams = (
            aws_resources_mlops_service_endpoint.add_resource("list_log_streams")
        )
        aws_resources_mlops_service_list_log_streams.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_service_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # get_log_stream
        aws_resources_mlops_service_get_log_stream = (
            aws_resources_mlops_service_endpoint.add_resource("get_log_stream")
        )
        aws_resources_mlops_service_get_log_stream.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_service_endpoint,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )



        ##### Models #####
        aws_resources_mlops_models = api.root.add_resource("models")

        # Describe Artifacts
        databricks_resources_artifacts_model_describe = (
            aws_resources_mlops_models.add_resource("describe")
        )
        databricks_resources_artifacts_model_describe.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_models,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )
        # Promote Model Registration
        databricks_resources_artifacts_model_promote = (
            aws_resources_mlops_models.add_resource("promote")
        )
        databricks_resources_artifacts_model_promote.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_models,
                proxy=False,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )


        ##### Credentials Generation #####
        aws_resources_credentials_generation = api.root.add_resource("credentials_generation")

        aws_resources_credentials_generation_aws = aws_resources_credentials_generation.add_resource(
            "aws"
        )

        aws_resources_credentials_generation_aws.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                credentials_lambda,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        aws_resources_credentials_generation_databricks = aws_resources_credentials_generation.add_resource(
            "databricks"
        )        

        aws_resources_credentials_generation_databricks.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                credentials_lambda,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )
        
        ##### Repos #####
        mlops_repos = api.root.add_resource("repos")

        # Create
        mlops_repos_create = mlops_repos.add_resource("create")
        mlops_repos_create.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=False,
                request_parameters={
                    "integration.request.header.X-Amz-Invocation-Type": "'Event'"
                },
                request_templates={"application/json": int_json},
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )

        # Describe
        mlops_repos_describe = mlops_repos.add_resource("describe")
        mlops_repos_describe.add_method(
            "POST",
            authorizer=authorizer_mlops,
            integration=apigateway.LambdaIntegration(
                aws_lambda_pipelines,
                proxy=True,
                integration_responses=[integration_response1, integration_response2],
            ),
            method_responses=method_responses,
        )



        # ==================================================
        # =================== DYNAMODB =====================
        # ==================================================

        dynamodb_class = DynamoDB(
            scope=self,
            id="dynamodb_stack",
        )

        table = dynamodb_class.build()

        # ==================================================
        # =============== LAMBDA LAYERS ====================
        # ==================================================

        self.boto3_requirements = read_requirements('boto3_requirements.txt')
        self.pandas_requirements = read_requirements('pandas_requirements.txt')


        boto3_layer = lambda_layer.build(
            layer_name="mlops_boto3_libraries",
            code_dir=f"{self.lambdas_directory}/lambda_layer_requirements",
            vpc=vpc,
            security_groups=[security_group_ec2_1, security_group_ec2_2],
            environments={
                "REQUIREMENTS": self.boto3_requirements,
                "S3_BUCKET": s3_bucket_layer.bucket_name,
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"]
            }
        )

        pandas_layer = lambda_layer.build(
            layer_name="mlops_pandas_libraries",
            code_dir=f"{self.lambdas_directory}/lambda_layer_requirements",
            vpc=vpc,
            security_groups=[security_group_ec2_1, security_group_ec2_2],
            environments={
                "REQUIREMENTS": self.pandas_requirements,
                "S3_BUCKET": s3_bucket_layer.bucket_name,
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"]
            }
        )

        # ==================================================
        # ============= LAMBDA COST TRACKING ===============
        # ==================================================

        bedrock_cost_tracking = LambdaBuilder.build(
            function_name="aws-mlops-foundation-models-bedrock-cost-tracking",
            code_dir=os.path.join(self.automation_lambda_code_dir, "bedrock", "cost_tracking"),
            runtime=lambda_.Runtime.PYTHON_3_10,
            timeout=Duration.seconds(900),
            memory_size=512,
            layers=[pandas_layer,mlops_common_requirements_layer],
            environment={
                "AWS_STS_REGIONAL_ENDPOINTS": "regional",
                "BEDROCK_REGION": region,
                "TABLE_NAME": "f1.f1ai_bedrock_cost_raw",
                "platform_automation_environment": self.context[
                    "platform_automation_environment"
                ],
            },
            event_schedule=events.Schedule.expression('cron(0 0 * * ? *)'),
        )

        # ==================================================
        # ============= MONITORING SERVICES ================
        # ==================================================

        aws_lambda_monitoring_error_logs = LambdaBuilder.build(
            function_name="aws-mlops-monitoring-error-logs",
            code_dir = os.path.join("../../python_scripts/automation_account_lambdas/"),
            handler="platform_monitoring_error_logs.lambda_handler",
            runtime=lambda_.Runtime.PYTHON_3_9,
            timeout=Duration.minutes(15),
            environment={
                "HTTPS_PROXY": self.context["network_proxy"],
                "HTTP_PROXY": self.context["network_proxy"],
                "http_proxy": self.context["network_proxy"],
                "https_proxy": self.context["network_proxy"],
                "no_proxy": self.context["network_no_proxy"],
                "platform_automation_environment": self.context[
                    "platform_automation_environment"]
            },
        )


        # DynamoDB table to keep track of request id and log stream

        _dyndb_tablename = "platform_error_logs_monitoring_requests"
        table = ddb.Table(
            self,
            id = "dynamodb_stack_request_id_table",
            table_name = _dyndb_tablename,
            partition_key=ddb.Attribute(
                name="request_id",
                type=ddb.AttributeType.STRING
            ),
            # time_to_live_attribute="ttl",
            removal_policy=RemovalPolicy.DESTROY
        )

        #Add Subscription filters to logs

        # Note - To add new cloudwatch log group to the list, make sure the log group is already created,
        # i.e for new lambdas at least one execution happened before adding the subscription filter.
        # If the specified log group is not present in the AWS account, this will fail.

        log_groups_to_add_subs_filter = [
            "/aws/lambda/lambda_authorizer",
            "/aws/lambda/aws-mlops-credentials-generation",
            "/aws/lambda/aws-mlops-service-endpoints",
            "/aws/lambda/aws-mlops-model-endpoints",
            "/aws/lambda/aws-mlops-pipelines",
            "/aws/lambda/aws-mlops-models",
            "/aws/lambda/aws-mlops-foundation-models-bedrock-cost-tracking",
            "/aws/lambda/f1ai_client_token_generation",
            "/aws/lambda/aws-mlops-monitoring-sagemaker-endpoints",
            "/aws/lambda/aws-mlops-platform-automations",
        ]

        client = boto3.client('logs', region_name=self.context["region"])

        ERROR_FILTER_NAME = "ErrorFilter"
        ERROR_FILTER_PATTERN = "[ERROR]"
        # ERROR_FILTER_PATTERN = "%^\\[ERROR\\]%"
        REPORT_FILTER_NAME = "ReportFilter"
        REPORT_FILTER_PATTERN = "REPORT RequestId:"


        for log_group_name in log_groups_to_add_subs_filter:
            # Create log group if it does not exist.
            _log_group_response = client.describe_log_groups(logGroupNamePrefix=log_group_name, limit=10)
            if len(_log_group_response["logGroups"] ) == 0:
                print(f"log group  {log_group_name} ===> NOT EXIST, creating the log group.")
                _new_log_group = LogGroup(self, f"{log_group_name}-log-group",
                    log_group_name=log_group_name
                )

            i_log_group = logs.LogGroup.from_log_group_name(self, log_group_name, log_group_name)
            log_group_base_name =  log_group_name.split("/")[-1]

            error_subscription_filter = logs.SubscriptionFilter(self, f"{log_group_base_name}-err-sub-cid",
                log_group=i_log_group,
                destination=destinations.LambdaDestination(aws_lambda_monitoring_error_logs),
                filter_pattern=logs.FilterPattern.all_terms(ERROR_FILTER_PATTERN),
                filter_name=ERROR_FILTER_NAME
            )

            report_subscription_filter = logs.SubscriptionFilter(self, f"{log_group_base_name}-filter-sub-cid",
                log_group=i_log_group,
                destination=destinations.LambdaDestination(aws_lambda_monitoring_error_logs),
                filter_pattern=logs.FilterPattern.all_terms(REPORT_FILTER_PATTERN),
                filter_name=REPORT_FILTER_NAME
            )

        aws_lambda_monitoring_sagemaker_endpoint = LambdaBuilder.build(
            function_name="aws-mlops-monitoring-sagemaker-endpoints",
            code_dir=os.path.join('../../python_scripts/automation_account_lambdas'),
            handler="platform_monitoring_sagemaker_endpoint.lambda_handler",
            runtime=lambda_.Runtime.PYTHON_3_9,
            timeout=Duration.minutes(15),
            layers=[
                mlops_common_requirements_layer
            ],
            environment={
                'HTTPS_PROXY': self.context['network_proxy'],
                'HTTP_PROXY': self.context['network_proxy'],
                'http_proxy': self.context['network_proxy'],
                'https_proxy': self.context['network_proxy'],
                'no_proxy': self.context['network_no_proxy'],
                'platform_automation_environment': self.context[
                    'platform_automation_environment'
                ],
                'region': self.context['region'],
                'node_environments_to_monitor': '22,23,24,31,32,33'
            },
            event_schedule=events.Schedule.rate(Duration.days(1)),
        )

