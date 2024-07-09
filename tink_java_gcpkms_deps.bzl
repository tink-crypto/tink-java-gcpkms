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

_GRPC_VERSION = "1.62.2"

TINK_JAVA_GCPKMS_MAVEN_ARTIFACTS = [
    "com.google.api.grpc:grpc-google-cloud-kms-v1:0.139.0",
    "com.google.api.grpc:proto-google-cloud-kms-v1:0.139.0",
    "com.google.api-client:google-api-client:2.2.0",
    "com.google.apis:google-api-services-cloudkms:v1-rev20221107-2.0.0",
    "com.google.auth:google-auth-library-oauth2-http:1.23.0",
    "com.google.auto.service:auto-service-annotations:1.1.1",
    "com.google.auto.service:auto-service:1.1.1",
    "com.google.auto:auto-common:1.2.2",
    "com.google.cloud:google-cloud-kms:2.48.0",
    "com.google.code.findbugs:jsr305:3.0.2",
    "com.google.errorprone:error_prone_annotations:2.28.0",
    # This is needed because of computing CRC32C checksums that's not available in java natively.
    "com.google.guava:guava:33.2.1-jre",
    "com.google.http-client:google-http-client-gson:1.44.2",
    "com.google.http-client:google-http-client:1.44.2",
    "com.google.oauth-client:google-oauth-client:1.34.1",
    "com.google.protobuf:protobuf-java:3.25.3",
    "io.grpc:grpc-api:%s" % _GRPC_VERSION,
    "io.grpc:grpc-inprocess:%s" % _GRPC_VERSION,
    "io.grpc:grpc-stub:%s" % _GRPC_VERSION,
    "io.grpc:grpc-testing:%s" % _GRPC_VERSION,
]

def tink_java_gcpkms_deps():
    """Bazel dependencies for tink-java-gcpkms."""

    # This is needed because tink-java@1.13.0 imports Protobuf v24.3, but grpc-google-cloud-kms
    # requires v25.3.
    if not native.existing_rule("com_google_protobuf"):
        # Feb 15th, 2024.
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-25.3",
            urls = ["https://github.com/protocolbuffers/protobuf/archive/refs/tags/v25.3.zip"],
            sha256 = "5156b22536feaa88cf95503153a6b2cd67cc80f20f1218f154b84a12c288a220",
        )

    if not native.existing_rule("tink_java"):
        # Apr 2nd, 2024.
        http_archive(
            name = "tink_java",
            urls = ["https://github.com/tink-crypto/tink-java/releases/download/v1.13.0/tink-java-1.13.0.zip"],
            strip_prefix = "tink-java-1.13.0",
            sha256 = "d795e05bd264d78f438670f7d56dbe38eeb14b16e5f73adaaf20b6bb2bd11683",
        )
