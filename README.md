# UIDAI POC

This repository has the following java files:

1. OtpClient.java : This has the code to send a OTP request to UIDAI
2. AuthClient.java : This has the code to send a Auth request to UIDAI

To compile 
```
javac OtpClient.java
```

To run
```
java OtpClient public.p12 publicauaforstagingservices
```

1. public.p12 is the file obtained from UIDAI itself (it is no longer publically avialable)
2. publicauaforstagingservices is the alias of the private key in the p12 file
3. the password of the p12 file is 'public'
