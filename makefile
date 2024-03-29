JC = javac
JFLAGS = -cp './src/jar/bcprov-ext-jdk15on-162.jar:.'
JFLAGS2 = -cp '../src/jar/bcprov-ext-jdk15on-162.jar:.'
JAR = https://www.bouncycastle.org/download/bcprov-ext-jdk15on-162.jar
CURRENT_DIR = $(PWD)


default: all

all:
	mkdir -p ./build/keys 
	mkdir -p ./src/jar
	cd ./src/jar && wget -N $(JAR)
	$(JC) $(JFLAGS) -d './build' src/*.java
	echo "Hello World!" > ./build/test.txt

gs:
	cd build && java $(JFLAGS2) RunGroupServer $(GPORT)

fs:
	cd build && java $(JFLAGS2) RunFileServer $(FPORT)

cl:
	cd build && java $(JFLAGS2) ClientDriver

gui:
	cd build && java $(JFLAGS2) ClientGui

rb:
	$(JC) $(JFLAGS) -d './build' src/*.java

clean:
	rm -r build
	rm -r src/jar

clear:
	rm -r ./build/*.bin
	rm -r ./build/shared_files/

reset:
	rm -r ./build/keys/*.key
	rm -r ./build/*.bin

test:
	echo $(CURRENT_DIR)
