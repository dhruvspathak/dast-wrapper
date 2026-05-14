variable "aws_region" {
  type        = string
  description = "AWS region for the EC2 deployment."
  default     = "ap-south-1"
}

variable "project_name" {
  type        = string
  description = "Name prefix for AWS resources."
  default     = "dast-platform"
}

variable "vpc_id" {
  type        = string
  description = "Existing VPC ID."
}

variable "subnet_id" {
  type        = string
  description = "Existing public subnet ID for the EC2 instance."
}

variable "admin_cidr_blocks" {
  type        = list(string)
  description = "CIDR blocks allowed to SSH to the instance."
}

variable "app_cidr_blocks" {
  type        = list(string)
  description = "CIDR blocks allowed to reach HTTP/HTTPS."
  default     = ["0.0.0.0/0"]
}

variable "key_name" {
  type        = string
  description = "EC2 key pair name."
}

variable "ami_id" {
  type        = string
  description = "Ubuntu Server 24.04 LTS AMI ID."
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type."
  default     = "t3a.large"
}

variable "ebs_volume_size_gb" {
  type        = number
  description = "Additional EBS volume size for persistent Docker data."
  default     = 100
}
