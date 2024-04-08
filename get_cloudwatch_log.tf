variable "stack_name" {
  type        = string
  description = "Dynatrace log forwarder name"
  default     = "dynatracelogs"
}

variable "dynatrace_environment_url" {
  description = "URL to Dynatrace environment"
}

variable "dynatrace_api_key" {
  description = "Dynatrace API key"
  sensitive   = true
}

variable "verify_ssl_target_active_gate" {
  description = "Verify SSL certificate for target ActiveGate"
  default     = false
}

variable "max_log_content_length" {
  description = "Maximum log content length"
  default     = 65536
}

variable "use_existing_active_gate" {
  description = "Use existing ActiveGate"
  default     = true
}

variable "dynatrace_paas_token" {
  description = "Dynatrace PaaS token"
  sensitive   = true
  default     = "dummyToken"
}

variable "tenant_id" {
  description = "Tenant ID"
  default     = "not_provided"
}

variable "deploy_ag_with_vpc" {
  type        = bool
  description = "Deploy ActiveGate with VPC"
  default     = false
}

data "aws_ssm_parameter" "latest_amazon_linux_ami_id" {
  name = "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {}

resource "aws_vpc" "vpc" {
  count                = var.deploy_ag_with_vpc ? 1 : 0

  cidr_block = "172.31.0.0/16"
  enable_dns_support = true
  enable_dns_hostnames = true
}

resource "aws_subnet" "public_subnet" {
  count                = var.deploy_ag_with_vpc ? 1 : 0

  vpc_id                = aws_vpc.vpc[count.index].id
  cidr_block            = "172.31.1.0/27"
  availability_zone     = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
}

resource "aws_subnet" "private_subnet" {
  count             = var.deploy_ag_with_vpc ? 1 : 0

  vpc_id            = aws_vpc.vpc[count.index].id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "172.31.2.0/27"
  map_public_ip_on_launch = false
}

resource "aws_internet_gateway" "igw" {
  count = var.deploy_ag_with_vpc ? 1 : 0

  vpc_id = aws_vpc.vpc[count.index].id
}

resource "aws_route_table" "public_route_table" {
  count = var.deploy_ag_with_vpc ? 1 : 0

  vpc_id = aws_vpc.vpc[count.index].id
}

resource "aws_route" "public_route_internet" {
  count             = var.deploy_ag_with_vpc ? 1 : 0

  route_table_id    = aws_route_table.public_route_table.*.id[count.index]
  destination_cidr_block = "0.0.0.0/0"
  gateway_id        = aws_internet_gateway.igw[count.index].id
}

resource "aws_route_table_association" "public_subnet_route_table_assoc" {
  count     = var.deploy_ag_with_vpc ? 1 : 0

  subnet_id = aws_subnet.public_subnet[count.index].id
  route_table_id = aws_route_table.public_route_table.*.id[count.index]
}

resource "aws_security_group" "security_group" {
  count            = var.deploy_ag_with_vpc ? 1 : 0

  vpc_id           = aws_vpc.vpc[count.index].id
  description      = "Allow ActiveGate ingress"
}

resource "aws_security_group_rule" "active_gate_inbound" {
  count                     = var.deploy_ag_with_vpc ? 1 : 0

  type                      = "ingress"
  from_port                 = 9999
  to_port                   = 9999
  protocol                  = "tcp"
  security_group_id         = aws_security_group.security_group.*.id[count.index]
  source_security_group_id  = aws_security_group.security_group.*.id[count.index]
}

resource "aws_instance" "ec2_active_gate" {
  count = var.use_existing_active_gate ? 0 : 1

  ami             = data.aws_ssm_parameter.latest_amazon_linux_ami_id.value
  instance_type   = "t3.small"
  subnet_id       = aws_subnet.public_subnet[count.index].id
  security_groups = [aws_security_group.security_group[count.index].id]
  tags = {
    Name = "${var.stack_name}-active-gate"
  }

  user_data = <<-EOF
    #!/bin/bash -xe
    wget -O Dynatrace-ActiveGate-Linux-x86.sh "${var.dynatrace_environment_url}/api/v1/deployment/installer/gateway/unix/latest?arch=x86&flavor=default" --header="Authorization: Api-Token ${var.dynatrace_paas_token}"
    wget https://ca.dynatrace.com/dt-root.cert.pem
    ( echo 'Content-Type: multipart/signed; protocol="application/x-pkcs7-signature"; micalg="sha-256"; boundary="--SIGNED-INSTALLER"'; echo ; echo ; echo '----SIGNED-INSTALLER' ; cat Dynatrace-ActiveGate-Linux-x86.sh ) | openssl cms -verify -CAfile dt-root.cert.pem > /dev/null
    /bin/sh Dynatrace-ActiveGate-Linux-x86.sh

    echo "[aws_monitoring]
    aws_monitoring_enabled = false
    [azure_monitoring]
    azure_monitoring_enabled = false
    [cloudfoundry_monitoring]
    cloudfoundry_monitoring_enabled = false
    [kubernetes_monitoring]
    kubernetes_monitoring_enabled = false
    [vmware_monitoring]
    vmware_monitoring_enabled = false
    [rpm]
    rpm_enabled = false
    [beacon_forwarder]
    beacon_forwarder_enabled = false
    [extension_controller]
    extension_controller_enabled = false
    [dbAgent]
    dbAgent_enabled = false
    [metrics_ingest]
    metrics_ingest_enabled = false
    [collector]
    MSGrouter = false" >> /var/lib/dynatrace/gateway/config/custom.properties

    systemctl restart dynatracegateway

    touch /home/ec2-user/userdata-ag-installation-success
  EOF
}

resource "aws_iam_role" "lambda_role" {
  name = "${var.stack_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action    = "sts:AssumeRole"
    }]
  })

  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  ]

  inline_policy {
    name = "cloudwatch_put_metric_data"

    policy = jsonencode({
      Version   = "2012-10-17"
      Statement = [{
        Effect   = "Allow"
        Action   = "cloudwatch:PutMetricData"
        Resource = "*"
      }]
    })
  }

  lifecycle {
    ignore_changes = [managed_policy_arns, inline_policy]
  }
}

resource "aws_lambda_function" "lambda" {
  filename      = "dynatrace-aws-log-forwarder-lambda.zip"
  function_name = "${var.stack_name}-function"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.8"
  memory_size   = 256
  timeout       = 60

  environment {
    variables = {
      DEBUG                  = false
      DYNATRACE_API_KEY      = var.dynatrace_api_key
      DYNATRACE_ENV_URL = var.deploy_ag_with_vpc ? "https://${element(aws_instance.ec2_active_gate.*.private_ip, 0)}:9999/e/${var.tenant_id}" : var.dynatrace_environment_url
      VERIFY_SSL             = var.verify_ssl_target_active_gate
      MAX_LOG_CONTENT_LENGTH = var.max_log_content_length
      CLOUD_LOG_FORWARDER    = "${data.aws_caller_identity.current.account_id}:${data.aws_region.current.name}:${var.stack_name}"
    }
  }
}

resource "aws_s3_bucket" "delivery_bucket" {
  bucket = "${var.stack_name}-delivery-bucket"

  force_destroy = true
}

resource "aws_s3_bucket_lifecycle_configuration" "example" {
  bucket = aws_s3_bucket.delivery_bucket.id

  rule {
    id = "rule-1"
    status = "Enabled"
    expiration {
      days = 7
    }
  }
}

resource "aws_s3_bucket_public_access_block" "delivery_bucket_access" {
  bucket = aws_s3_bucket.delivery_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "delivery_stream_role" {
  name = "${var.stack_name}-delivery-stream-role"

  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        Service = "firehose.amazonaws.com"
      }
      Action    = "sts:AssumeRole"
    }]
  })

  inline_policy {
    name = "firehose_delivery_policy"

    policy = jsonencode({
      Version   = "2012-10-17"
      Statement = [{
        Effect   = "Allow"
        Action   = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.delivery_bucket.arn,
          "${aws_s3_bucket.delivery_bucket.arn}/*"
        ]
      }]
    })
  }
}

resource "aws_kinesis_firehose_delivery_stream" "firehose_log_streams" {
  name = "${var.stack_name}-firehose-delivery-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    bucket_arn = aws_s3_bucket.delivery_bucket.arn
    role_arn   = aws_iam_role.delivery_stream_role.arn

    buffering_interval = 60
    buffering_size = 5

    compression_format = "GZIP"
    error_output_prefix = "error-"
    prefix              = "success-"

    processing_configuration {
      enabled = true

      processors {
        type = "Lambda"

       parameters {
          parameter_name  = "LambdaArn"
          parameter_value = aws_lambda_function.lambda.arn
        }
      }
    }
  }
}

resource "aws_iam_policy" "firehose_lambda_invocation_policy" {
  name        = "firehose_lambda_invocation_policy"
  description = "Policy for Firehose Lambda invocation"

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "lambda:InvokeFunction",
          "lambda:GetFunctionConfiguration",
        ]
        Resource = [
          aws_lambda_function.lambda.arn,
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "delivery_stream_role_lambda_policy_attachment" {
  role       = aws_iam_role.delivery_stream_role.name
  policy_arn = aws_iam_policy.firehose_lambda_invocation_policy.arn
}

resource "aws_iam_role" "cloudwatch_logs_role" {
  name               = "${var.stack_name}-cloud-watch-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  description = "Role for subscription filters (to write to Firehose)"
}

resource "aws_iam_policy" "cloudwatch_logs_policy" {
  name   = "${var.stack_name}-cloud-watch-policy"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "firehose:PutRecord",
          "firehose:PutRecordBatch",
        ]
        Resource = aws_kinesis_firehose_delivery_stream.firehose_log_streams.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs_policy_attachment" {
  role       = aws_iam_role.cloudwatch_logs_role.name
  policy_arn = aws_iam_policy.cloudwatch_logs_policy.arn
}

resource "aws_cloudwatch_dashboard" "self_monitoring_dashboard" {
  dashboard_name = "DynatraceLogForwarder-SelfMonitoring-${data.aws_region.current.name}-${var.stack_name}"
  dashboard_body = jsonencode({
    "widgets": [
            {
              "height": 6,
              "width": 12,
              "y": 6,
              "x": 0,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Kinesis record age", "function_name", "${aws_lambda_function.lambda.function_name}", { "stat": "Minimum" } ],
                [ "...", { "stat": "Average" } ],
                [ "..." ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "stat": "Maximum",
                "period": 60,
                "liveData": true,
                "setPeriodToTimeRange": true,
                "legend": {
                  "position": "bottom"
                },
                "title": "Kinesis - record age"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 18,
              "x": 12,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Kinesis record.data decompressed size", "function_name", "${aws_lambda_function.lambda.function_name}" ],
                [ "...", { "stat": "Average" } ],
                [ "...", { "stat": "Maximum" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "stat": "Minimum",
                "period": 60,
                "title": "Kinesis - record.data decompressed size"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 18,
              "x": 0,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Kinesis record.data compressed size", "function_name", "${aws_lambda_function.lambda.function_name}" ],
                [ "...", { "stat": "Average" } ],
                [ "...", { "stat": "Maximum" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "stat": "Minimum",
                "period": 60,
                "title": "Kinesis - record.data compressed size"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 24,
              "x": 0,
              "type": "metric",
              "properties": {
                "metrics": [
                [ { "expression": "SEARCH('{AWS/Logs,FilterName,LogGroupName,DestinationType} FilterName=\"${var.stack_name}\" MetricName=\"ForwardedLogEvents\"', 'Sum', 60)", "id": "e1", "region": "${data.aws_region.current.name}" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "period": 300,
                "stat": "Average",
                "title": "Log Groups - log entries received from CloudWatch"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 30,
              "x": 12,
              "type": "metric",
              "properties": {
                "metrics": [
                [ { "expression": "SEARCH('{AWS/Logs,FilterName,LogGroupName,DestinationType} FilterName=\"${var.stack_name}\" MetricName=\"ForwardedBytes\"', 'Sum', 60)", "id": "e1", "region": "${data.aws_region.current.name}" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "period": 300,
                "stat": "Average",
                "title": "Log Groups - bytes received from CloudWatch"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 30,
              "x": 0,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Batches prepared", "function_name", "${aws_lambda_function.lambda.function_name}" ],
                [ ".", "Batches delivered", ".", "." ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "stat": "Sum",
                "period": 60,
                "title": "Delivery - batches"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 36,
              "x": 0,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Log entries prepared", "function_name", "${aws_lambda_function.lambda.function_name}" ],
                [ ".", "Log entries delivered", ".", "." ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "stat": "Sum",
                "period": 60,
                "title": "Delivery - log entries"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 36,
              "x": 12,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Data volume prepared", "function_name", "${aws_lambda_function.lambda.function_name}" ],
                [ ".", "Data volume delivered", ".", "." ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "title": "Delivery - data volume",
                "period": 60,
                "stat": "Sum"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 48,
              "x": 0,
              "type": "metric",
              "properties": {
                "metrics": [
                [ { "expression": "SEARCH('{DT/LogsStreaming,function_name,status_code} function_name=\"${aws_lambda_function.lambda.function_name}\" MetricName=\"Requests status code count\"', 'Sum', 60)", "id": "e1", "region": "${data.aws_region.current.name}" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "title": "Requests - status codes",
                "period": 300,
                "stat": "Average"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 42,
              "x": 0,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Requests duration", "function_name", "${aws_lambda_function.lambda.function_name}", { "stat": "Minimum" } ],
                [ "..." ],
                [ "...", { "stat": "Maximum" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "period": 60,
                "stat": "Average",
                "title": "Requests - durations"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 48,
              "x": 12,
              "type": "metric",
              "properties": {
                "metrics": [
                [ { "expression": "SEARCH('{DT/LogsStreaming,function_name,type} function_name=\"${aws_lambda_function.lambda.function_name}\" MetricName=\"Issues\"', 'Sum', 60)", "id": "e1", "region": "${data.aws_region.current.name}" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "stat": "Sum",
                "period": 60,
                "title": "Delivery - issues"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 42,
              "x": 12,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Log attr trimmed", "function_name", "${aws_lambda_function.lambda.function_name}" ],
                [ ".", "Log content trimmed", ".", "." ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "period": 60,
                "title": "Logs - trimmed",
                "stat": "Sum"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 6,
              "x": 12,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Log age min", "function_name", "${aws_lambda_function.lambda.function_name}", { "stat": "Minimum" } ],
                [ "DT/LogsStreaming", "Log age avg", "function_name", "${aws_lambda_function.lambda.function_name}" ],
                [ "DT/LogsStreaming", "Log age max", "function_name", "${aws_lambda_function.lambda.function_name}", { "stat": "Maximum" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "title": "Logs - age",
                "region": "${data.aws_region.current.name}",
                "period": 60,
                "stat": "Average"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 0,
              "x": 0,
              "type": "metric",
              "properties": {
                "view": "timeSeries",
                "stacked": false,
                "metrics": [
                [ "AWS/Lambda", "Invocations", "FunctionName", "${aws_lambda_function.lambda.function_name}" ]
                ],
                "region": "${data.aws_region.current.name}",
                "title": "Lambda - invocations"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 0,
              "x": 12,
              "type": "metric",
              "properties": {
                "view": "timeSeries",
                "stacked": false,
                "metrics": [
                [ "AWS/Lambda", "Duration", "FunctionName", "${aws_lambda_function.lambda.function_name}" ]
                ],
                "region": "${data.aws_region.current.name}",
                "title": "Lambda - duration"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 12,
              "x": 12,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "AWS/Lambda", "Errors", "FunctionName", "${aws_lambda_function.lambda.function_name}" ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "stat": "Sum",
                "period": 60,
                "title": "Lambda errors"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 12,
              "x": 0,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Kinesis record age", "function_name", "${aws_lambda_function.lambda.function_name}", { "label": "Kinesis records" } ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "stat": "SampleCount",
                "period": 60,
                "title": "Kinesis - records number"
              }
            },
            {
              "height": 6,
              "width": 12,
              "y": 24,
              "x": 12,
              "type": "metric",
              "properties": {
                "metrics": [
                [ "DT/LogsStreaming", "Kinesis record.data decompressed size", "function_name", "${aws_lambda_function.lambda.function_name}" ]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${data.aws_region.current.name}",
                "stat": "Sum",
                "period": 60,
                "title": "Kinesis - sum record.data decompressed size"
              }
            }
            ]
  })
}
