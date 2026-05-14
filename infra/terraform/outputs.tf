output "instance_id" {
  value = aws_instance.app.id
}

output "public_ip" {
  value = aws_eip.app.public_ip
}

output "security_group_id" {
  value = aws_security_group.instance.id
}

output "docker_data_volume_id" {
  value = aws_ebs_volume.docker_data.id
}
