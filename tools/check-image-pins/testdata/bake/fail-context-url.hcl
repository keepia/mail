target "a" {
  context = "https://example.org/team/repo.git#main"
}
target "b" {
  context = "git@example.org:team/repo.git"
}
# want-lines: 2 5
