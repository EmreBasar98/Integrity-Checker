Information Security Assignment #3
Integrity Checker Project

Due to usage of sun.security.tools.keytool,an internal java package, project must be build with in the format of
    javac -XDignore.symbol.file ...

Main method is in the ichecker.java, so the final format of build is
    javac -XDignore.symbol.file ichecker.java

Arguments can be given in any order to program.
Type of files in the monitored path can be any format.

java ichecker createCert -k PriKey -c PubKeyCertificate

java ichecker createReg -r RegFile -p Path -l LogFile -h Hash -k PriKey

java ichecker check -r RegFile -p Path -l LogFile -h Hash -c PubKeyCertificate