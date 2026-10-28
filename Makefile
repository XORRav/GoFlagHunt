.PHONY: build build-linux build-windows build-all clean

build:
	go build -ldflags="-s -w" -o goreap.exe .

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o goreap .

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o goreap.exe .

build-all: build-linux build-windows

clean:
	rm -f goreap goreap.exe
