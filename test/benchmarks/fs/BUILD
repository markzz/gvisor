load("//tools:defs.bzl", "go_test")

package(licenses = ["notice"])

go_test(
    name = "bazel_test",
    size = "enormous",
    srcs = ["bazel_test.go"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)

go_test(
    name = "fio_test",
    size = "enormous",
    srcs = ["fio_test.go"],
    deps = [
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
        "@com_github_docker_docker//api/types/mount:go_default_library",
    ],
)
