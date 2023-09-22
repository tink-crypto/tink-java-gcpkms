"""Dependencies of Tink Java Google Cloud KMS."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

TINK_JAVA_GCPKMS_MAVEN_ARTIFACTS = [
    "com.google.api-client:google-api-client:2.2.0",
    "com.google.apis:google-api-services-cloudkms:v1-rev20221107-2.0.0",
    "com.google.auth:google-auth-library-oauth2-http:1.5.3",
    "com.google.http-client:google-http-client:1.43.1",
    "com.google.http-client:google-http-client-gson:1.43.1",
    "com.google.oauth-client:google-oauth-client:1.34.1",
    "com.fasterxml.jackson.core:jackson-core:2.13.1",
]

def tink_java_gcpkms_deps():
    """Bazel dependencies for tink-java-gcpkms."""
    if not native.existing_rule("tink_java"):
        # Sep 22nd, 2023.
        http_archive(
            name = "tink_java",
            urls = ["https://github.com/tink-crypto/tink-java/releases/download/v1.11.0/tink-java-1.11.0.zip"],
            strip_prefix = "tink-java-1.11.0",
            sha256 = "2bd264c2f0c474c77e2d1e04c627398e963b7a6d0164cfb743ab60a59ab998bd",
        )
