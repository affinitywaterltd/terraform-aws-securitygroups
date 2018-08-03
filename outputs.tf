output "admin_sg_id" {
  description = "Security group to provide access to our administration systems"
  value       = "${aws_security_group.admin_sg.id}"
}

output "remote_access_sg_id" {
  description = "Security group to provide access to our administration systems"
  value       = "${aws_security_group.remote_access_sg.id}"
}

output "open_http_https_sg_id" {
  description = "Security group to provide access to our administration systems"
  value       = "${aws_security_group.open_http_https_sg.id}"
}
