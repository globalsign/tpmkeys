# Contributing

We really appreciate contributions, but they must meet the following requirements:

* Please start by opening a new issue describing the bug or feature you're
  intending to fix, as it's helpful to know what people are working on.
* Follow the normal process of forking the project, and setup a new branch to
  work in. It's important that each group of changes be done in separate
  branches in order to ensure that a pull request only includes the commits
  related to that bug or feature.
* Pull requests should target the `development` branch, not the `master`
  branch.
* Existing tests should pass and any new code should be covered with its own
  test(s). Look at some of the existing tests if you're unsure how to go about
  it.
* Go makes it very simple to ensure properly formatted code, so always run
  `go fmt` on your code before committing it. 
* Code should pass `golint` and `go vet`.
* New functions should be [documented](https://blog.golang.org/godoc-documenting-go-code)
  clearly.

**Thanks** for helping!
