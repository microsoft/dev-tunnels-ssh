module github.com/microsoft/dev-tunnels-ssh/test/go/ssh-test

go 1.21

require (
	github.com/microsoft/dev-tunnels-ssh/src/go v0.0.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/microsoft/dev-tunnels-ssh/src/go => ../../../src/go
