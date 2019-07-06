JC = javac
JFLAGS = -cp './build/jar/bcprov-ext-jdk15on-162.jar:.'
JFLAGS2 = -cp './jar/bcprov-ext-jdk15on-162.jar:.'
JAR = https://www.bouncycastle.org/download/bcprov-ext-jdk15on-162.jar
CURRENT_DIR = $(PWD)

default: all

all:
	mkdir -p ./build/jar
	cd ./build/jar && wget -N $(JAR)
	$(JC) $(JFLAGS) -d './build' src/*.java

groupserver:
	cd build && java $(JFLAGS2) RunGroupServer 8765

fileserver:
	cd build && java $(JFLAGS2) RunFileServer 4321

client:
	cd build && java $(JFLAGS2) ClientDriver

rebuild:
	$(JC) $(JFLAGS) -d './build' src/*.java

rebuild_all:
	make clean
	make all

clean:
	rm -r build

test:
	echo $(CURRENT_DIR)
