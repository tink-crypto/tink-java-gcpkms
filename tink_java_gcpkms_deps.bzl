"""Dependencies of Tink Java Google Cloud KMS."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

TINK_JAVA_GCPKMS_MAVEN_TEST_ARTIFACTS = [
    "com.google.truth:truth:1.4.4",
    "org.junit.jupiter:junit-jupiter-api:5.11.3",
]

TINK_JAVA_GCPKMS_MAVEN_TOOLS_ARTIFACTS = [
    "org.ow2.asm:asm-commons:9.7.1",
    "org.ow2.asm:asm:9.7.1",
    "org.pantsbuild:jarjar:1.7.2",
]

_GRPC_VERSION = "1.70.0"

TINK_JAVA_GCPKMS_MAVEN_ARTIFACTS = [
    "com.google.api.grpc:grpc-google-cloud-kms-v1:0.154.0",
    "com.google.api.grpc:proto-google-cloud-kms-v1:0.154.0",
    "com.google.api-client:google-api-client:2.7.2",
    "com.google.apis:google-api-services-cloudkms:v1-rev20241111-2.0.0",
    "com.google.auth:google-auth-library-oauth2-http:1.33.1",
    "com.google.auto.service:auto-service-annotations:1.1.1",
    "com.google.auto.service:auto-service:1.1.1",
    "com.google.auto:auto-common:1.2.2",
    "com.google.cloud:google-cloud-kms:2.63.0",
    "com.google.code.findbugs:jsr305:3.0.2",
    "com.google.errorprone:error_prone_annotations:2.36.0",
    # This is needed because of computing CRC32C checksums that's not available in java natively.
    "com.google.guava:guava:33.4.0-jre",
    "com.google.http-client:google-http-client-gson:1.46.3",
    "com.google.http-client:google-http-client:1.46.3",
    "com.google.oauth-client:google-oauth-client:1.39.0",
    "com.google.protobuf:protobuf-java:3.25.5",
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
        # Release from 2024-02-15.
        http_archive(
            name = "com_google_protobuf",
            strip_prefix = "protobuf-25.3",
            urls = ["https://github.com/protocolbuffers/protobuf/archive/refs/tags/v25.3.zip"],
            sha256 = "5156b22536feaa88cf95503153a6b2cd67cc80f20f1218f154b84a12c288a220",
        )

    # MacOS Sequoia requires zlib 1.3.1, because of incompatibility with com_google_protobuf.
    # See https://github.com/bazelbuild/bazel/issues/25124.
    if not native.existing_rule("zlib"):
        zlib_version = "1.3.1"
        zlib_sha256 = "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"
        http_archive(
            name = "zlib",
            build_file = "@com_google_protobuf//:third_party/zlib.BUILD",
            sha256 = zlib_sha256,
            strip_prefix = "zlib-%s" % zlib_version,
            urls = ["https://github.com/madler/zlib/releases/download/v{v}/zlib-{v}.tar.gz".format(v = zlib_version)],
        )

    if not native.existing_rule("tink_java"):
        # Release from 2024-08-30.
        http_archive(
            name = "tink_java",
            urls = ["https://github.com/tink-crypto/tink-java/releases/download/v1.15.0/tink-java-1.15.0.zip"],
            strip_prefix = "tink-java-1.15.0",
            sha256 = "e246f848f7749e37f558955ecb50345b04d79ddb9d8d1e8ae19f61e8de530582",
        )
