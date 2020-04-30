GOPATH=$(shell pwd)
LIB= ./src/Authentication/authentication.go \
	./src/Core/core.go \
	./src/Core/coreProxy.go \
	./src/Core/coreConnection.go \
	./src/Encryption/encryption.go \
	./src/FileParser/jsonParser.go \
	./src/FileParser/csvParser.go \
	./src/Logging/logging.go

LOCAL_LIB= ./src/Local.main/local.go \
 		   ./src/Local.main/Local/localServerInfo.go

SERVER_LIB= ./src/Server.main/server.go \
			./src/Server.main/Server/server.go \
			./src/Server.main/Server/localSession.go


all : mySSLocal mySSServer

mySSServer : $(SERVER_LIB) $(LIB)
	GOPATH=$(GOPATH) go build -o mySSServer Server.main

mySSLocal : $(LOCAL_LIB) $(LIB)
	GOPATH=$(GOPATH) go build -o mySSLocal Local.main

windows : mySSLocalWin.exe

mac : mySSLocalMac

linux : mySSLocal

mySSLocalWin.exe : $(LOCAL_LIB) $(LIB)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOPATH=$(GOPATH) go build -o mySSLocalWin.exe Local.main

mySSLocalMac : $(LOCAL_LIB) $(LIB)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 GOPATH=$(GOPATH) go build -o mySSLocalMac Local.main

clean:
	rm -f *.a
	rm -f mySSLocal*
	rm -f mySSServer*