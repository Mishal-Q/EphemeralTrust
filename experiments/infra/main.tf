terraform {
  required_version = ">= 1.6, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
provider "aws" { region = "us-east-1" }
variable "repository" {
  type = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.repository))
    error_message = "Use exact OWNER/REPOSITORY."
  }
}
variable "oidc_subject_repository" {
  type        = string
  description = "Exact repository component printed by the GitHub-only OIDC preflight, including immutable IDs when present."
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+(@[0-9]+)?/[A-Za-z0-9_.-]+(@[0-9]+)?$", var.oidc_subject_repository))
    error_message = "Copy the repository component from the OIDC preflight."
  }
}
variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Expected 12-digit AWS account ID."
  }
}
variable "installation" {
  type    = string
  default = "research"
  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.installation))
    error_message = "Use 1–20 lowercase letters, digits or hyphens."
  }
}
variable "create_oidc_provider" {
  type    = bool
  default = false
}
data "aws_caller_identity" "current" {}
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_oidc_provider ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}
data "aws_iam_openid_connect_provider" "existing" {
  count = var.create_oidc_provider ? 0 : 1
  arn   = "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com"
}
locals {
  provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.existing[0].arn
  subjects = {
    main      = "repo:${var.oidc_subject_repository}:environment:ep2-main"
    alternate = "repo:${var.oidc_subject_repository}:environment:ep2-alternate"
  }
  run_roles = "arn:aws:iam::${var.account_id}:role/ep2-run-*"
}
resource "aws_s3_bucket" "canary" {
  bucket_prefix = "ep2-canary-${var.installation}-"
  force_destroy = false
  lifecycle {
    precondition {
      condition     = data.aws_caller_identity.current.account_id == var.account_id
      error_message = "Wrong AWS account; refusing provisioning."
    }
  }
  tags = { EphemeralTrustPhase = "2" }
}
resource "aws_s3_bucket_public_access_block" "canary" {
  bucket                  = aws_s3_bucket.canary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_ownership_controls" "canary" {
  bucket = aws_s3_bucket.canary.id
  rule { object_ownership = "BucketOwnerEnforced" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "canary" {
  bucket = aws_s3_bucket.canary.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_iam_role" "controller" {
  name                 = "ep2-controller-${var.installation}"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = local.provider_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        "token.actions.githubusercontent.com:sub" = values(local.subjects)
      } }
    }]
  })
  tags = { EphemeralTrustPhase = "2" }
}
resource "aws_iam_role_policy" "controller" {
  role = aws_iam_role.controller.id
  name = "ep2-scoped-controller"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "IsolatedExperimentalRoles"
        Effect   = "Allow"
        Action   = ["iam:CreateRole", "iam:TagRole", "iam:GetRole", "iam:DeleteRole", "iam:UpdateAssumeRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:GetRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies"]
        Resource = local.run_roles
      },
      {
        Sid      = "IndependentChainVerifier"
        Effect   = "Allow"
        Action   = ["sts:AssumeRole"]
        Resource = "arn:aws:iam::${var.account_id}:role/ep2-run-*-chain"
      },
      {
        Sid      = "CanaryObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.canary.arn}/ep2-run-*/*"
      },
      {
        Sid      = "CanaryConfigurationReadback"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketPolicy", "s3:GetBucketOwnershipControls", "s3:GetEncryptionConfiguration", "s3:GetBucketPublicAccessBlock"]
        Resource = aws_s3_bucket.canary.arn
      },
      {
        Sid      = "IdentityAndManagementEventHistory"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity", "cloudtrail:LookupEvents"]
        Resource = "*"
      }
    ]
  })
}
output "live_config" {
  value = {
    account_id                           = var.account_id
    repository                           = var.repository
    region                               = "us-east-1"
    controller_role_arn                  = aws_iam_role.controller.arn
    provider_arn                         = local.provider_arn
    bucket                               = aws_s3_bucket.canary.id
    subjects                             = local.subjects
    zero_cost_reviewed                   = false
    dedicated_experiment_scope_confirmed = false
    max_trace_seconds                    = 7200
    max_live_runs_per_dispatch           = 1
  }
}
