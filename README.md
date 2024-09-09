# UIDAI POC

This repository has the following java files:

1. OtpClient.java : This has the code to send a OTP request to UIDAI
2. AuthClient.java : This has the code to send a Auth request to UIDAI

There is no maven project, and the files are independent of each other (and self conatained). 

There are no external libraries, and the files compile with java 21

The test data (UID, AUA Key, ASA Key) is hard-wired in the individual files - it is picked up from the UIDAI test site.


To compile 
```
javac AuthClient.java
```
or
```
javac OtpClient.java
```


To run
```
java OtpClient public.p12 publicauaforstagingservices
```
or
```
java AuthClient public.p12 publicauaforstagingservices
```


1. public.p12 is the file obtained from UIDAI itself (it is no longer publically avialable)
2. publicauaforstagingservices is the alias of the private key in the p12 file
3. the password of the p12 file is 'public'
