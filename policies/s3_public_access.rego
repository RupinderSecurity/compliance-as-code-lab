package compliance.s3

default allow = false

deny contains msg if {
    input.block_public_acls == false
    msg := "S3 bucket allows public ACLs - violates PCI DSS 1.3 and FedRAMP AC-3"
}

deny contains msg if {
    input.restrict_public_buckets == false
    msg := "S3 bucket does not restrict public buckets - violates FedRAMP AC-3"
}