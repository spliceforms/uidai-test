# UIDAI POC

This repository has the following java files:

1. OtpClient.java : This has the code to send a OTP request to UIDAI
2. AuthClient.java : This has the code to send a Auth request to UIDAI
3. AuthClientBC.java : This has the code to send a Auth request to UIDAI (using BouncyCastle)

There is no maven project, and the files are independent of each other (and self conatained). 

There are no external libraries, and the files compile with java 21

The test data (UID, AUA Key, ASA Key) is hard-wired in the individual files - it is picked up from the UIDAI test site.


## OtpClient
To compile 
```
javac OtpClient.java
```

To run with the hardwired UID (999941057058)
```
java OtpClient public.p12 publicauaforstagingservices
```

To run with a different UID (eg; 999933119405)
```
java OtpClient public.p12 publicauaforstagingservices 999933119405
```


## AuthClient
To compile 
```
javac AuthClient.java
```

To run with the hardwired UID (999941057058)
```
java AuthClient public.p12 publicauaforstagingservices 123456
```

To run with a different UID (eg; 999933119405)
```
java AuthClient public.p12 publicauaforstagingservices 123456 999933119405 
```

To send KYC instead of Auth with a different UID (eg; 999933119405)
```
java AuthClient public.p12 publicauaforstagingservices 123456 999933119405 kyc
```

## AuthClientBC
To compile 
```
javac -cp bcprov-jdk18on-1.78.1.jar AuthClientBC.java
```

To run
```
java -cp bcprov-jdk18on-1.78.1.jar AuthClientBC.java public.p12 publicauaforstagingservices
```


### What you need to run

1. You need the public.p12 file to run (this is not committed to the repository) - you should write to authsupport@uidai.net.in to get the file.
    * The file we received from UIDAI was called public.p12.
    * In the commands above, you must replace public.p12 with the file you receive. 


2. You need the alias (you can find that out from the public.p12 file itself by running keytool) 
    * publicauaforstagingservices is the alias of the private key in the p12 file that we received


3. The password of the p12 file & the private key. 
    * The file we received had the password public
    * If the password is different for you, change it using keytool. (The password is hardwired in the code).

4. KycClient hardcodes the Auth XML, and this will fail since UIDAI requires the `ts` to be within 24 hours. Use AuthClient to generate a new one & replace it. 