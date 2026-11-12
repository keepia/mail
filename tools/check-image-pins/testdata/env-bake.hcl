# Used through BUILDX_BAKE_FILE by TestRepoModeIgnoresCallerEnv (a clean
# decoy the repository mode must not read) and TestBuildMode (a build that
# reads it must be checked as it is).
target "a" {
  context = "https://example.invalid/env.git"
}

target "root" {
  context = "."
}
