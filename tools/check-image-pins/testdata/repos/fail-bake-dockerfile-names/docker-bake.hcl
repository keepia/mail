# Dockerfiles the walk would not read: names it does not recognise, and a
# file under prototypes/, which the walk skips (reviews A 1c, B 1). The
# bake rule checks every target's Dockerfile wherever it is.
group "default" {
  targets = ["a", "b", "p"]
}

target "a" {
  dockerfile = "build.txt"
}

target "b" {
  dockerfile = "Dockerfile-alt"
}

target "p" {
  context    = "prototypes"
  dockerfile = "x/Dockerfile"
}
