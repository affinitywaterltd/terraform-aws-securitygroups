# Outbound rule! Currently attached to admin SG only

resource "aws_security_group_rule" "outbound" {
  type        = "egress"
  from_port   = -1
  to_port     = -1
  protocol    = -1
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = aws_security_group.admin_sg.id
}

# Admin SG
#
#
resource "aws_security_group" "admin_sg" {
  name        = "Core_System_Admin"
  description = "Allow all inbound traffic"
  vpc_id      = var.vpc_id
  tags        = local.base_tags
}

resource "aws_security_group_rule" "anti-virus" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-ce54c4b3"
  description              = "Anti-virus"

  security_group_id = aws_security_group.admin_sg.id
}

resource "aws_security_group_rule" "darktrace" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-585aca25"
  description              = "Darktrace"

  security_group_id = aws_security_group.admin_sg.id
}

resource "aws_security_group_rule" "domains_controllers" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-c4ad3db9"
  description              = "Domain Controllers"

  security_group_id = aws_security_group.admin_sg.id
}


resource "aws_security_group_rule" "domains_controllers_shared_infra" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "986618351900/sg-0a39fde358a87c506"
  description              = "Shared Infra - Domain Controllers"

  security_group_id = aws_security_group.admin_sg.id
}

resource "aws_security_group_rule" "monitoring" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-9b50c0e6"
  description              = "Monitoring"

  security_group_id = aws_security_group.admin_sg.id
}

resource "aws_security_group_rule" "monitoring_agent" {
  type                     = "ingress"
  from_port                = 8885
  to_port                  = 8887
  protocol                 = "tcp"
  source_security_group_id = "986618351900/sg-08391c4926a12a0b8"
  description              = "Monitoring - Agent"

  security_group_id = aws_security_group.admin_sg.id
}

resource "aws_security_group_rule" "zabbix" {
  type                     = "ingress"
  from_port                = 10050
  to_port                  = 10051
  protocol                 = "tcp"
  source_security_group_id = "986618351900/sg-0bb782d4b1234a3f6"
  description              = "Shared Infra - Zabbix"

  security_group_id = aws_security_group.admin_sg.id
}


resource "aws_security_group_rule" "patching" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-6350c01e"
  description              = "Patching"

  security_group_id = aws_security_group.admin_sg.id
}

resource "aws_security_group_rule" "ansible" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-916cfcec"
  description              = "Ansible"

  security_group_id = aws_security_group.admin_sg.id
}

resource "aws_security_group_rule" "solarwinds_agent" {
  type                     = "ingress"
  from_port                = 17790
  to_port                  = 17790
  protocol                 = "tcp"
  source_security_group_id = "986618351900/sg-0cc2c86839d14fe1c"
  description              = "solarwinds_agent"

  security_group_id = aws_security_group.admin_sg.id
}

resource "aws_security_group_rule" "solarwinds_wmi" {
  type                     = "ingress"
  from_port                = 135
  to_port                  = 135
  protocol                 = "tcp"
  source_security_group_id = "986618351900/sg-0cc2c86839d14fe1c"
  description              = "solarwinds_wmi"

  security_group_id = aws_security_group.admin_sg.id
}

resource "aws_security_group_rule" "ping" {
  type        = "ingress"
  from_port   = -1
  to_port     = -1
  protocol    = "icmp"
  cidr_blocks = ["10.0.0.0/8"]
  description = "Internal Ping"

  security_group_id = aws_security_group.admin_sg.id
}

resource "aws_security_group_rule" "dynamic" {
  type        = "ingress"
  from_port   = 49152
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
  description = "Dynamic Port Range"

  security_group_id = aws_security_group.admin_sg.id
}

# Remote Access
#
#

resource "aws_security_group" "remote_access_sg" {
  name        = "Core_Remote_Access"
  description = "Allows remote access - SSH and RDP - from local network"
  vpc_id      = var.vpc_id
  tags        = local.base_tags
}

resource "aws_security_group_rule" "SSH" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
  description = "Internal SSH"

  security_group_id = aws_security_group.remote_access_sg.id
}

resource "aws_security_group_rule" "RDP" {
  type        = "ingress"
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
  description = "Internal RDP"

  security_group_id = aws_security_group.remote_access_sg.id
}

# Public Web Server
#
#

resource "aws_security_group" "open_http_https_sg" {
  name        = "Core_HTTP_HTTPS_All"
  description = "Allows open access from HTTP and HTTPS from anywhere"
  vpc_id      = var.vpc_id
  tags        = local.base_tags
}

resource "aws_security_group_rule" "HTTP_Open" {
  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = aws_security_group.open_http_https_sg.id
}

resource "aws_security_group_rule" "HTTPS_Open" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = aws_security_group.open_http_https_sg.id
}

resource "aws_security_group_rule" "HTTP_Internal" {
  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.open_http_https_sg.id
}

resource "aws_security_group_rule" "HTTPS_Internal" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.open_http_https_sg.id
}

resource "aws_security_group" "internal_http_https_sg" {
  name        = "Core_HTTP_HTTPS_Internal"
  description = "Allows open access from HTTP and HTTPS from anywhere"
  vpc_id      = var.vpc_id
  tags        = local.base_tags
}

resource "aws_security_group_rule" "HTTP_Internal_traffic" {
  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.internal_http_https_sg.id
}

resource "aws_security_group_rule" "HTTPS_Internal_traffic" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.internal_http_https_sg.id
}

## Citrix

resource "aws_security_group" "citrix_sg" {
  name        = "Core_Citrix"
  description = "For Citrix created machines"
  vpc_id      = var.vpc_id
  tags        = local.base_tags
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_8082" {
  type        = "ingress"
  from_port   = 8082
  to_port     = 8083
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_80" {
  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_443" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_1494" {
  type        = "ingress"
  from_port   = 1494
  to_port     = 1494
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_2598" {
  type        = "ingress"
  from_port   = 2598
  to_port     = 2598
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_8008" {
  type        = "ingress"
  from_port   = 8008
  to_port     = 8008
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_2512" {
  type        = "ingress"
  from_port   = 2512
  to_port     = 2513
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_8080" {
  type        = "ingress"
  from_port   = 8080
  to_port     = 8080
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

resource "aws_security_group_rule" "upd_range_Internal1" {
  type        = "ingress"
  from_port   = 16500
  to_port     = 16509
  protocol    = "udp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

resource "aws_security_group_rule" "upd_range_Internal2" {
  type        = "ingress"
  from_port   = 49152
  to_port     = 65535
  protocol    = "udp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

resource "aws_security_group_rule" "upd_9_Internal" {
  type        = "ingress"
  from_port   = 9
  to_port     = 9
  protocol    = "udp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_8100" {
  type        = "ingress"
  from_port   = 8100
  to_port     = 8100
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_1433" {
  type        = "ingress"
  from_port   = 1433
  to_port     = 1434
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "citrix_delivery_135" {
  type        = "ingress"
  from_port   = 135
  to_port     = 135
  protocol    = "tcp"
  cidr_blocks = ["10.31.103.203/32", "10.31.106.65/32"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "citrix_director_5985" {
  type        = "ingress"
  from_port   = 5985
  to_port     = 5985
  protocol    = "tcp"
  cidr_blocks = ["10.31.100.33/32", "10.31.104.120/32"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_3389" {
  type        = "ingress"
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "citrix_delivery_389" {
  type        = "ingress"
  from_port   = 389
  to_port     = 389
  protocol    = "tcp"
  cidr_blocks = ["10.31.103.203/32", "10.31.106.65/32"]

  security_group_id = aws_security_group.citrix_sg.id
}

# TF-UPGRADE-TODO: In Terraform v0.11 and earlier, it was possible to begin a
# resource name with a number, but it is no longer possible in Terraform v0.12.
#
# Rename the resource and run `terraform state mv` to apply the rename in the
# state. Detailed information on the `state move` command can be found in the
# documentation online: https://www.terraform.io/docs/commands/state/mv.html
resource "aws_security_group_rule" "internal_445" {
  type        = "ingress"
  from_port   = 445
  to_port     = 445
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = aws_security_group.citrix_sg.id
}

