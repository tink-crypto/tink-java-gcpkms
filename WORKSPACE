workspace(name = "tink_java_gcpkms")

load("@tink_java_gcpkms//:tink_java_gcpkms_deps.bzl", "TINK_JAVA_GCPKMS_MAVEN_ARTIFACTS", "TINK_JAVA_GCPKMS_MAVEN_TOOLS_ARTIFACTS", "TINK_JAVA_GCPKMS_MAVEN_TEST_ARTIFACTS", "tink_java_gcpkms_deps")

tink_java_gcpkms_deps()

load("@tink_java//:tink_java_deps.bzl", "TINK_MAVEN_ARTIFACTS", "tink_java_deps")

tink_java_deps()

load("@tink_java//:tink_java_deps_init.bzl", "tink_java_deps_init")

tink_java_deps_init()

load("@rules_jvm_external//:defs.bzl", "maven_install")
load("@rules_jvm_external//:specs.bzl", "maven")

maven_install(
    artifacts = TINK_MAVEN_ARTIFACTS +
                TINK_JAVA_GCPKMS_MAVEN_ARTIFACTS +
                TINK_JAVA_GCPKMS_MAVEN_TEST_ARTIFACTS +
                TINK_JAVA_GCPKMS_MAVEN_TOOLS_ARTIFACTS + [
        # This is needed to add grpc-core while removing a circular dependency
        # between grpc-core and grpc-util.
        #
        # See https://github.com/grpc/grpc-java/issues/10576.
        maven.artifact(
            artifact = "grpc-core",
            exclusions = [
                "io.grpc:grpc-util",
            ],
            group = "io.grpc",
            version = "1.62.2",
        ),
    ],
    repositories = [
        "https://maven.google.com",
        "https://repo1.maven.org/maven2",
    ],
)
