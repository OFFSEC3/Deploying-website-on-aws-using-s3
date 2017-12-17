provider "aws" {
  region = "us-east-1"
}

# What I get from this template
# ✔ Two buckets
# ✔ Ec2 IAM role with bucket write and read access
# ✔ Ec2 with httpd and WP
# ✔ `-> via provisioning
# ✔ WebDMZ security group for Ec2
# ✔ RDS instance with mysql
# ✔ SG for 3306 from WebDMZ SG
# ✔ ALB with Ec2 as target
# ✔ Route53 connection

resource "aws_key_pair" "deployer" {
  key_name = "terraform_deployer"
  public_key = "Put an actual public key here"
}

resource "aws_s3_bucket" "lab-wp-site" {
  bucket = "lab-wp-site"
  acl    = "private"
}

resource "aws_s3_bucket" "lab-wp-media" {
  bucket = "lab-wp-media"
  acl    = "private"
}

resource "aws_iam_role" "lab_s3_admin_iam_role" {
  name = "tlab-s3-admin"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Service": "ec2.amazonaws.com"
    },
    "Action": "sts:AssumeRole"
  }]
}
EOF
}

resource "aws_iam_policy" "tlab-s3-policy" {
  name        = "tllab_s3_policy"
  path        = "/"
  description = "Terraform Lab Policy for S3"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_policy_attachment" "lab-attach" {
  name       = "lab-attachment"
  roles      = ["${aws_iam_role.lab_s3_admin_iam_role.name}"]
  policy_arn = "${aws_iam_policy.tlab-s3-policy.arn}"
}

resource "aws_iam_instance_profile" "lab_s3_admin_iam_profile" {
  name = "tlab_s3_admin"
  role = "${aws_iam_role.lab_s3_admin_iam_role.name}"
}

resource "aws_security_group" "lab_web_dmz" {
  name        = "lab_web_dmz_ec2"
  description = "Allow web inbound"

  ingress {
    from_port   = 0
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "lab_web_lb" {
  name        = "lab_web_lb"
  description = "Allow web inbound"

  ingress {
    from_port   = 0
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "lab_rds" {
  name        = "lab_rds"
  description = "Allow mysql inbound"

  ingress {
    from_port       = 0
    to_port         = 3306
    protocol        = "tcp"
    security_groups = ["${aws_security_group.lab_web_dmz.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  depends_on = ["aws_security_group.lab_web_dmz"]
}

resource "aws_instance" "wp-front" {
  ami                    = "ami-2452275e"
  instance_type          = "t2.micro"
  vpc_security_group_ids = ["${aws_security_group.lab_web_dmz.id}"]
  iam_instance_profile   = "${aws_iam_instance_profile.lab_s3_admin_iam_profile.name}"
  key_name               = "${aws_key_pair.deployer.key_name}"
  depends_on             = ["aws_security_group.lab_web_dmz", "aws_key_pair.deployer"]
  provisioner "remote-exec" {
    inline = [
      "sudo mkdir -p /root/.ssh",
      "sudo cp /home/ec2-user/.ssh/authorized_keys /root/.ssh/authorized_keys"
      ]
    connection { 
      type = "ssh"
      user = "ec2-user"
      private_key = "${file("~/.ssh/terraform_deployer.rsa")}"
    }
  }
  provisioner "remote-exec" {
    script = "files/first_round.sh"
    connection { 
      type = "ssh"
      user = "root"
      private_key = "${file("~/.ssh/terraform_deployer.rsa")}"
    }
  }
  provisioner "file" {
    source = "files/htaccess.txt"
    destination = "/var/www/html/.htaccess"
    connection { 
      type = "ssh"
      user = "root"
      private_key = "${file("~/.ssh/terraform_deployer.rsa")}"
    }
  }
  provisioner "file" {
    source = "files/httpd.txt"
    destination = "/etc/httpd/conf/httpd.conf"
    connection { 
      type = "ssh"
      user = "root"
      private_key = "${file("~/.ssh/terraform_deployer.rsa")}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "systemctl reload httpd.service"
    ]
    connection { 
      type = "ssh"
      user = "root"
      private_key = "${file("~/.ssh/terraform_deployer.rsa")}"
    }
  }
  provisioner "file" {
    source = "files/wp-config.php"
    destination = "/var/www/html/wp-config.php"
    connection { 
      type = "ssh"
      user = "root"
      private_key = "${file("~/.ssh/terraform_deployer.rsa")}"
    }
  }
  provisioner "file" {
    source = "files/s3_sync.txt"
    destination = "/tmp/s3_sync"
    connection { 
      type = "ssh"
      user = "root"
      private_key = "${file("~/.ssh/terraform_deployer.rsa")}"
    }
  }
  provisioner "remote-exec" {
    inline = [
      "sed -i s/REPLACE_ME_CF_DOM/${aws_cloudfront_distribution.lab_s3_distribution.domain_name}/g /var/www/html/.htaccess",
      "sed -i s/REPLACE_ME_DB_PASS/${aws_db_instance.lab-wp-rds.password}/g /var/www/html/wp-config.php",
      "sed -i s/REPLACE_ME_DB_HOST/${aws_db_instance.lab-wp-rds.address}/g /var/www/html/wp-config.php",
      "crontab /tmp/s3_sync",
      "rm -f /tmp/s3_sync",
      "rm -rf /root/.ssh/authorized_keys"
    ]
    connection { 
      type = "ssh"
      user = "root"
      private_key = "${file("~/.ssh/terraform_deployer.rsa")}"
    }
  }
}

resource "aws_db_instance" "lab-wp-rds" {
  allocated_storage      = 10
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "5.6.37"
  instance_class         = "db.t2.micro"
  name                   = "lab_wp_db"
  username               = "lab_wp_user"
  password               = "PUT A REAL DB PASS HERE"
  parameter_group_name   = "default.mysql5.6"
  vpc_security_group_ids = ["${aws_security_group.lab_rds.id}"]
  depends_on             = ["aws_security_group.lab_rds"]
  skip_final_snapshot    = true
}

resource "aws_lb" "tlab-elb" {
  name            = "tlab-elb"
  internal        = false
  security_groups = ["${aws_security_group.lab_web_lb.id}"]

  subnets = [
    "subnet-72299416",
    "subnet-4e2fff71",
    "subnet-d03917dc",
    "subnet-51e2331a",
    "subnet-6d373c37",
    "subnet-ffcddbd3",
  ]
}

resource "aws_lb_target_group" "tlab_tg" {
  name     = "tlab-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "vpc-09e52171"
}

resource "aws_lb_listener" "tlab_listener" {
  load_balancer_arn = "${aws_lb.tlab-elb.arn}"
  port              = "80"
  protocol          = "HTTP"

  default_action {
    target_group_arn = "${aws_lb_target_group.tlab_tg.arn}"
    type             = "forward"
  }
}

resource "aws_lb_target_group_attachment" "tlab_target_attachment" {
  target_group_arn = "${aws_lb_target_group.tlab_tg.arn}"
  target_id        = "${aws_instance.wp-front.id}"
  port             = 80
}

resource "aws_cloudfront_origin_access_identity" "lab_s3_cf_origin" {
  comment = "Terraform Lab Trialing"
}

resource "aws_cloudfront_distribution" "lab_s3_distribution" {
  origin {
    domain_name = "${aws_s3_bucket.lab-wp-media.bucket_domain_name}"
    origin_id   = "S3-thisuniquethang"

    s3_origin_config {
      origin_access_identity = "${aws_cloudfront_origin_access_identity.lab_s3_cf_origin.cloudfront_access_identity_path}"
    }
  }

  enabled             = true
  comment             = "Some comment"
  default_root_object = "index.html"

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-thisuniquethang"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  depends_on = ["aws_s3_bucket.lab-wp-media"]
}

resource "aws_s3_bucket_policy" "lab-wp-media-cf" {
  bucket = "${aws_s3_bucket.lab-wp-media.id}"
  policy =<<POLICY
{
    "Version": "2008-10-17",
    "Id": "PolicyForCloudFrontPrivateContent",
    "Statement": [
        {
            "Sid": "1",
            "Effect": "Allow",
            "Principal": {
                "AWS": "${aws_cloudfront_origin_access_identity.lab_s3_cf_origin.iam_arn}"
            },
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::lab-wp-media/*"
        }
    ]
}
POLICY
}

resource "aws_route53_record" "www" {
  zone_id = "Z1PTD1RTD5MFZJ"
  name    = "cstll.be"
  type    = "A"

  alias {
    name                   = "${aws_lb.tlab-elb.dns_name}"
    zone_id                = "${aws_lb.tlab-elb.zone_id}"
    evaluate_target_health = true
  }
}
