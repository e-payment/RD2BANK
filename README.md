RD2BANK
=======

# Test & Build
```
## Test ##
$ mvn clean test

## Package ##
$ mvn clean package -Dmaven.test.skip
```

# Certificate
## create keystore
```
#SHA256
keytool -genkey -alias rd2bank -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=RD2BANK, OU=RD, O=Organization, L=Bangkok, ST=Bangkok, C=TH" -keystore key/rd2bank.p12 -validity 3650

#SHA1
keytool -genkey -alias rd2bank -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=RD2BANK, OU=RD, O=Organization, L=Bangkok, ST=Bangkok, C=TH" -keystore key/rd2bank-sha1.p12 -validity 3650 -sigalg SHA1withRSA

#LIST
keytool -list -v -storetype pkcs12 -keystore key/rd2bank.p12
```

## export public key
```
## PEM (ASCII) ##
keytool -exportcert -alias rd2bank -storetype PKCS12 -keystore key/rd2bank.p12 -rfc -file key/rd2bank.cer
keytool -exportcert -alias rd2bank -storetype PKCS12 -keystore key/rd2bank-sha1.p12 -rfc -file key/rd2bank-sha1.cer

## DER (BINARY) ##
keytool -exportcert -alias rd2bank -storetype PKCS12 -keystore key/rd2bank.p12 -file key/rd2bank.DER.cer
```

# Mapping XML

## JAXB from XSD schema
```
xjc -d src/main/java -p th.go.rd.rd2bank src/main/resources/schema/RD2BANK.xsd
xjc -d src/main/java -p th.go.rd.bank2rd src/main/resources/schema/BANK2RD.xsd
```

## StAX API
```
???
```
