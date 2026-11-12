target "a" {
  context = "/srv/src"
}
target "b" {
  context = "../other"
}
target "c" {
  context = "${SRC}"
}
target "d" {
  context = SRC
}
# want-lines: 2 5 8 11
