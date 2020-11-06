load("//tools:defs.bzl", "bzl_library", "go_binary")

package(licenses = ["notice"])

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = [
        "//:sandbox",
    ],
)

go_binary(
    name = "check_docker_net_config",
    srcs = ["check_docker_net_config.go"],
)
