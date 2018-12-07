# Outbound rule! Currently attached to admin SG only

resource "aws_security_group_rule" "outbound" {
  type        = "egress"
  from_port   = -1
  to_port     = -1
  protocol    = -1
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = "${aws_security_group.admin_sg.id}"
}

# Admin SG
#
#
resource "aws_security_group" "admin_sg" {
  name        = "Core_System_Admin"
  description = "Allow all inbound traffic"
  vpc_id      = "${var.vpc_id}"
  tags        = "${local.base_tags}"
}

resource "aws_security_group_rule" "anti-virus" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-ce54c4b3"
  description              = "Anti-virus"

  security_group_id = "${aws_security_group.admin_sg.id}"
}

resource "aws_security_group_rule" "darktrace" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-585aca25"
  description              = "Darktrace"

  security_group_id = "${aws_security_group.admin_sg.id}"
}

resource "aws_security_group_rule" "domains_controllers" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-c4ad3db9"
  description              = "Domain Controllers"

  security_group_id = "${aws_security_group.admin_sg.id}"
}

resource "aws_security_group_rule" "monitoring" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-9b50c0e6"
  description              = "Monitoring"

  security_group_id = "${aws_security_group.admin_sg.id}"
}

resource "aws_security_group_rule" "patching" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-6350c01e"
  description              = "Patching"

  security_group_id = "${aws_security_group.admin_sg.id}"
}

resource "aws_security_group_rule" "ansible" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = "739672810541/sg-916cfcec"
  description              = "Ansible"

  security_group_id = "${aws_security_group.admin_sg.id}"
}

resource "aws_security_group_rule" "ping" {
  type        = "ingress"
  from_port   = -1
  to_port     = -1
  protocol    = "icmp"
  cidr_blocks = ["10.0.0.0/8"]
  description = "Internal Ping"

  security_group_id = "${aws_security_group.admin_sg.id}"
}

resource "aws_security_group_rule" "dynamic" {
  type        = "ingress"
  from_port   = 49152
  to_port     = 65535
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
  description = "Dynamic Port Range"

  security_group_id = "${aws_security_group.admin_sg.id}"
}

# Remote Access
#
#

resource "aws_security_group" "remote_access_sg" {
  name        = "Core_Remote_Access"
  description = "Allows remote access - SSH and RDP - from local network"
  vpc_id      = "${var.vpc_id}"
  tags        = "${local.base_tags}"
}

resource "aws_security_group_rule" "SSH" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
  description = "Internal SSH"

  security_group_id = "${aws_security_group.remote_access_sg.id}"
}

resource "aws_security_group_rule" "RDP" {
  type        = "ingress"
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]
  description = "Internal RDP"

  security_group_id = "${aws_security_group.remote_access_sg.id}"
}

# Public Web Server
#
#

resource "aws_security_group" "open_http_https_sg" {
  name        = "Core_HTTP_HTTPS_All"
  description = "Allows open access from HTTP and HTTPS from anywhere"
  vpc_id      = "${var.vpc_id}"
  tags        = "${local.base_tags}"
}

resource "aws_security_group_rule" "HTTP_Open" {
  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = "${aws_security_group.open_http_https_sg.id}"
}

resource "aws_security_group_rule" "HTTPS_Open" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = "${aws_security_group.open_http_https_sg.id}"
}

resource "aws_security_group_rule" "HTTP_Internal" {
  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.open_http_https_sg.id}"
}

resource "aws_security_group_rule" "HTTPS_Internal" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.open_http_https_sg.id}"
}

resource "aws_security_group" "internal_http_https_sg" {
  name        = "Core_HTTP_HTTPS_Internal"
  description = "Allows open access from HTTP and HTTPS from anywhere"
  vpc_id      = "${var.vpc_id}"
  tags        = "${local.base_tags}"
}

resource "aws_security_group_rule" "HTTP_Internal_traffic" {
  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.internal_http_https_sg.id}"
}

resource "aws_security_group_rule" "HTTPS_Internal_traffic" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.internal_http_https_sg.id}"
}


## Citrix

resource "aws_security_group" "citrix_sg" {
  name        = "Core_Citrix"
  description = "For Citrix created machines"
  vpc_id      = "${var.vpc_id}"
  tags        = "${local.base_tags}"
}

resource "aws_security_group_rule" "8082_Internal" {
  type        = "ingress"
  from_port   = 8082
  to_port     = 8083
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}


resource "aws_security_group_rule" "80_Internal" {
  type        = "ingress"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "443_Internal" {
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "1494_Internal" {
  type        = "ingress"
  from_port   = 1494
  to_port     = 1494
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "2598_Internal" {
  type        = "ingress"
  from_port   = 2598
  to_port     = 2598
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "8008_Internal" {
  type        = "ingress"
  from_port   = 8008
  to_port     = 8008
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "2512_Internal" {
  type        = "ingress"
  from_port   = 2512
  to_port     = 2513
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "8080_Internal" {
  type        = "ingress"
  from_port   = 8080
  to_port     = 8080
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "upd_range_Internal1" {
  type        = "ingress"
  from_port   = 16500
  to_port     = 16509
  protocol    = "udp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "upd_range_Internal2" {
  type        = "ingress"
  from_port   = 49152
  to_port     = 65535
  protocol    = "udp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "upd_9_Internal" {
  type        = "ingress"
  from_port   = 9
  to_port     = 9
  protocol    = "udp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "8100_Internal" {
  type        = "ingress"
  from_port   = 8100
  to_port     = 8100
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "1433_Internal" {
  type        = "ingress"
  from_port   = 1433
  to_port     = 1434
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "135_citrix_delivery" {
  type        = "ingress"
  from_port   = 135
  to_port     = 135
  protocol    = "tcp"
  cidr_blocks = ["10.31.103.203/32", "10.31.106.65/32"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "5985_citrix_director" {
  type        = "ingress"
  from_port   = 5985
  to_port     = 5985
  protocol    = "tcp"
  cidr_blocks = ["10.31.100.33/32", "10.31.104.120/32"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "3389_Internal" {
  type        = "ingress"
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "389_citrix_delivery" {
  type        = "ingress"
  from_port   = 389
  to_port     = 389
  protocol    = "tcp"
  cidr_blocks = ["10.31.103.203/32", "10.31.106.65/32"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}

resource "aws_security_group_rule" "445_Internal" {
  type        = "ingress"
  from_port   = 445
  to_port     = 445
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/8"]

  security_group_id = "${aws_security_group.citrix_sg.id}"
}