target "a" {
  context = "."
  dockerfile-inline = <<EOT
FROM debian:trixie-slim
EOT
}
# want-lines: 3 3
