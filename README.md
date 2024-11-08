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

### NSDL

1. OtpClientNsdl
To compile 
```
javac OtpClientNsdl.java
```

To run
```
java OtpClientNsdl public.p12 publicauaforstagingservices 352116 578796332042
```
2. AuthClientNsdl
To compile
```
javac AuthClientNsdl.java
```
To run
```
java AuthClientNsdl public.p12 publicauaforstagingservices 825978
```

3. KycClientNsdl
To compile
```
javac KycClientNsdl.java
```
To run
```
java KycClientNsdl public.p12 publicauaforstagingservices 300371 578796332042 kyc
```

### NPCI

To run Npci kyc you need to copy .pfx file received from bank same folder

1. OtpClientNpci
   
To compile 
```
javac OtpClientNpci.java
```

To Run 
```
java OtpClientNpci
```

2. KycClientNpci.java
   
To compile 
```
javac KycClientNpci.java
```

To Run first put otp received from OtpClientNpci into KycCleintNpci also add same txn id used in OtpClientNpci 
```
java KycClientNpci
```

## OtpClient With cloudHSM
To compile
```
javac OtpClientHSM.java
```
To run
```
java OtpClientHSM
```


#### In order to run OtpClientHSM.java file, your machine(Windows or Linux) should satisfy below prerequisits.
    * HSM driver installation on machine(We are using Windows 11 )
    * JDK installtion (we are using Java 17)
    * IP whitelisting should happend at HSM side(we are using up 45.58.32.151)
    * nFast service should be up(open cmd at ../nCipher/nFast/bin and do enquiry.exe)
    * .p12 or.pfx file and cert should be mapped at cloud HSM and  shoud have alias generated for same
   



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
