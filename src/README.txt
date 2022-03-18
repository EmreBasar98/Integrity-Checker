Information Security Assignment #2
Integrity Checker Project

We used sun.security.tools.keytool external library so external lib linking shoold be enabled with the following flag;
    javac -XDignore.symbol.file ...

The final compilation command is like shown below
    javac -XDignore.symbol.file ichecker.java


java ichecker createCert -k PriKey -c PubKeyCertificate

java ichecker createReg -r RegFile -p Path -l LogFile -h MD5 -k PriKey

java ichecker check -r RegFile -p Path -l LogFile -h MD5 -c PubKeyCertificate
