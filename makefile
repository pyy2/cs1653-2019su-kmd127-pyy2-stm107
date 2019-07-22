JC = javac
FLAGS = -cp 
JARPATH = ./src/jar/bcprov-ext-jdk15on-162.jar:.
JAR = https://www.bouncycastle.org/download/bcprov-ext-jdk15on-162.jar

DEMOPATH = -cp '../../src/jar/bcprov-ext-jdk15on-162.jar:.'

default: all

all:
	mkdir -p ./build/keys 
	mkdir -p ./src/jar
	cd ./src/jar && wget -N $(JAR)
	$(JC) $(FLAGS) $(JARPATH) -d './build' src/*.java
	echo "Hello World!" > ./build/test.txt

gs:
	cd build && java $(FLAGS) .$(JARPATH) RunGroupServer $(GPORT)

fs:
	cd build && java $(FLAGS) .$(JARPATH) RunFileServer $(FPORT)

cl:
	cd build && java $(FLAGS) .$(JARPATH) ClientDriver

gui:
	cd build && java $(FLAGS) .$(JARPATH) ClientGui

rb:
	$(JC) $(FLAGS) $(JARPATH) -d './build' src/*.java

clean:
	rm -r build
	rm -r src/jar

clear:
	rm -r ./build/*.bin
	rm -r ./build/shared_files/

reset:
	rm -r ./build/keys/*.key
	rm -r ./build/*.bin

demo:
	make clean
	mkdir -p ./src/jar
	mkdir -p ./build/gs/keys
	mkdir -p ./build/fs/keys
	mkdir -p ./build/fs/shared_files
	mkdir -p ./build/cl1/keys
	mkdir -p ./build/cl2/keys
	mkdir -p ./build/cl3/keys
	echo "Hello From Client 1!" > ./build/cl1/test.txt
	echo "Hello From Client 2!" > ./build/cl2/test.txt
	echo "Hello From Client 3!" > ./build/cl3/test.txt

	cd ./src/jar && wget -N $(JAR)
	make build_demo

build_demo:
	$(JC) $(FLAGS) $(JARPATH) -d './build/gs' ./src/*.java
	$(JC) $(FLAGS) $(JARPATH) -d './build/fs' ./src/*.java
	$(JC) $(FLAGS) $(JARPATH) -d './build/cl1' ./src/*.java
	$(JC) $(FLAGS) $(JARPATH) -d './build/cl2' ./src/*.java
	$(JC) $(FLAGS) $(JARPATH) -d './build/cl3' ./src/*.java

gsd:
	cd build/gs && java $(FLAGS) ../.$(JARPATH) RunGroupServer $(GPORT)

fsd:
	cd build/fs && java $(FLAGS) ../.$(JARPATH) RunFileServer $(GPORT)

cl1d:
	cd build/cl1 && java $(FLAGS) ../.$(JARPATH) ClientDriver $(GPORT)

cl2d:
	cd build/cl2 && java $(FLAGS) ../.$(JARPATH) ClientDriver $(GPORT)

cl3d:
	cd build/cl3 && java $(FLAGS) ../.$(JARPATH) ClientDriver $(GPORT)
