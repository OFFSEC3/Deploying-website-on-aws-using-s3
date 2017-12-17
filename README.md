# Capstone for Udemy Cloud learning


## What you get

This is a project designed to fire up

* A blank Wordpress site
* On EC2
* Load-balanced via an ELB
* Caching via cloudfront for media uploads
* s3 hosting for cloudfronted media
* Route53 DNS

## Limitations
This Terraform template is complete, but there are still a number of
assumptions it makes concerning:

* Subnets
* The VPC
* The Route53 Zone

Once those items are manually configured, then this should work in
just about any blank environment
