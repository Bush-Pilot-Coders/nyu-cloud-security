terraform {
  backend "s3" {
    bucket = "nyu-cloudsec-final-project-terraform"
    key    = "terraform.tfstate"
    region = "us-east-1"
  }
}
