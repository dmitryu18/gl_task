provider "aws" {
region = "ua-central-1"

data "aws_availability_zones" "available" {}

data "aws_ami" "latest_windows_2019" {
	owner = ["amazon"]
	most_recent = true
	filter {
		name = "name"
		values = ["Windows_server-2019-English-Full-Base.*"]
	}
}
/*
output "latest_windows_2019_ami_id" {
	value = data.aws_ami.latest_windows_2019.id
}
*/ 

resorce "aws_security_group" "my_server" {
	name = "Dynamic Security Group"
	
	dynamic "ingress" {
		for_each = ["80", "443", "8080"]
		content {
			from_port 	= ingress.value
			to_port    	= ingress.value
			protocol   	= "tcp"
			cidr_blocks	= ["0.0.0.0/0"]
		}	
	}
	
	ingress {
		from_port	= 22
		to_port		= 22
		protocol   	= "tcp"
		cidr_blocks	= ["10.0.0.0/16"]
	}
		
	ingress {
		from_port	= 0
		to_port		= 0
		protocol   	= ".1"
		cidr_blocks	= ["0.0.0.0/0"]
	}
	
	tags = {
		Name  = "UDV"
		Owner = "Udalov Dmitriy"
	}
/* 	
	lifecycle {
    create_before_destroy = true
	}
*/
}

resource "aws_launch_configuration" "as_conf" {
  name_prefix     = "web_config"
  image_id        = data.aws_ami.latest_windows_2019.id
  instance_type   = "t2.micro"
  security_groups = [aws_security_group.web.id]
  user_data 	  = file("startiss.ps1")
  
  lifecycle {
	  create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "bar" { 
  name                 = "terraform-asg"
  launch_configuration = aws_launch_configuration.as_conf.name
  min_size             = 2
  max_size             = 2
  min_elb_capacity	   = 2
  vpc_zone_identifier  = [aws_default_subnet.default_az1.id, aws_default_subnet.default_az2 .id] 
  load_balancers 	   = [aws_lb.test.name]
  health_check_type    = "ELB"
  

  lifecycle {
    create_before_destroy = true
  }	

tags = [ 
	{
	key = "Name" 
	value = "Server1" 
	propagate_at_launch = true
	},
	{
	key = "Owner" 
	value = "UDV" 
	propagate_at_launch = true
	},
]

lifecycle {
	create_before_destroy = true
	}
}

/* internal LBs can only use ipv4 */

resource "aws_lb" "test" {
  name               = "test-lb"
  load_balancer_type = "network"
  availability_zones = [data.aws_awailability_zones.available.names[0],
  data.aws_awailability_zones.available.names[1]]
  security_groups    = [aws_security_group.my_server.id]
  /*subnets            = aws_default_subnet" "default_az.*.id*/
  enable_deletion_protection = true
	listener {
		lb_port	 		  = 80
		lbprotocol 		  = "http"
		instance_port 	  = 80
		instance_protocol = "http"
	}
	health_check {
		health_threshold    = 2
		unhealthy_threshold = 2
		timeout			  	= 3
		target 			  	= "HTTP:80/"
		interval			= 10
	}
	tags = {
		Name = "Server-test-lb"
	} 
}

resource "aws_default_subnet" "default_az1"{
	availability_zone = data.aws_awailability_zones.avalable.names[0]
}

resource "aws_default_subnet" "default_az2"{
	availability_zone = data.aws_awailability_zones.avalable.names[1]
}
		
		
		
		
		
		
		
		
		
		
		