all: email.pb.go

%.pb.go:	%.proto
	protoc --go_out=. $<
