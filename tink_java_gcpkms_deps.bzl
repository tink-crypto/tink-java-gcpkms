"""Dependencies of Tink Java Google Cloud KMS."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

TINK_JAVA_GCPKMS_MAVEN_TEST_ARTIFACTS = [
    "com.google.truth:truth:0.44",
    "junit:junit:4.13.2",
]

TINK_JAVA_GCPKMS_MAVEN_TOOLS_ARTIFACTS = [
    "org.ow2.asm:asm-commons:7.0",
    "org.ow2.asm:asm:7.0",
    "org.pantsbuild:jarjar:1.7.2",
]

TINK_JAVA_GCPKMS_MAVEN_ARTIFACTS = [
    "com.google.api.grpc:proto-google-cloud-kms-v1:0.124.0",
    "com.google.api-client:google-api-client:2.2.0",
    "com.google.apis:google-api-services-cloudkms:v1-rev20221107-2.0.0",
    "com.google.auth:google-auth-library-oauth2-http:1.20.0",
    "com.google.auto.service:auto-service-annotations:1.1.1",
    "com.google.auto.service:auto-service:1.1.1",
    "com.google.auto:auto-common:1.2.2",
    "com.google.cloud:google-cloud-kms:2.31.0",
    "com.google.code.findbugs:jsr305:3.0.2",
    "com.google.errorprone:error_prone_annotations:2.22.0",
    "com.google.http-client:google-http-client-gson:1.43.3",
    "com.google.http-client:google-http-client:1.43.3",
    "com.google.oauth-client:google-oauth-client:1.34.1",
    "com.google.protobuf:protobuf-java:3.25.1",
]

def tink_java_gcpkms_deps():
    """Bazel dependencies for tink-java-gcpkms."""
    if not native.existing_rule("tink_java"):
        http_archive(
            name = "tink_java",
            urls = ["https://github.com/tink-crypto/tink-java/releases/download/v1.12.0/tink-java-1.12.0.zip"],
            strip_prefix = "tink-java-1.12.0",
            sha256 = "c5f79c4f51e55d5c7bbd52c0b17fc8eeedf36d74a231e134882f9c4a74c3fbb1",
        )
