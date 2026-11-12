target "app" {
  context    = "." # target "--file=decoy.hcl"
  dockerfile = "build.txt"
  contexts = { base = "docker-image://busybox:latest" }
}
