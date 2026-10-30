.PHONY: build build-linux build-windows build-all clean

build:
	go build -ldflags="-s -w" -o wraithflag.exe .

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o wraithflag .

build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o wraithflag.exe .

build-all: build-linux build-windows

clean:
	rm -f wraithflag wraithflag.exe
