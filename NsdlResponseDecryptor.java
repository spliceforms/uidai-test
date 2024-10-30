{\rtf1\ansi\ansicpg1252\cocoartf2820
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fnil\fcharset0 Menlo-Regular;}
{\colortbl;\red255\green255\blue255;\red70\green137\blue204;\red24\green24\blue24;\red193\green193\blue193;
\red67\green192\blue160;\red202\green202\blue202;\red66\green179\blue255;\red167\green197\blue152;\red194\green126\blue101;
\red212\green214\blue154;\red89\green138\blue67;\red140\green211\blue254;\red183\green111\blue179;\red205\green173\blue106;
}
{\*\expandedcolortbl;;\cssrgb\c33725\c61176\c83922;\cssrgb\c12157\c12157\c12157;\cssrgb\c80000\c80000\c80000;
\cssrgb\c30588\c78824\c69020;\cssrgb\c83137\c83137\c83137;\cssrgb\c30980\c75686\c100000;\cssrgb\c70980\c80784\c65882;\cssrgb\c80784\c56863\c47059;
\cssrgb\c86275\c86275\c66667;\cssrgb\c41569\c60000\c33333;\cssrgb\c61176\c86275\c99608;\cssrgb\c77255\c52549\c75294;\cssrgb\c84314\c72941\c49020;
}
\paperw11900\paperh16840\margl1440\margr1440\vieww29200\viewh17840\viewkind0
\deftab720
\pard\pardeftab720\partightenfactor0

\f0\fs24 \cf2 \cb3 \expnd0\expndtw0\kerning0
\outl0\strokewidth0 \strokec2 package\cf4 \strokec4  \cf5 \strokec5 org\cf6 \strokec6 .\cf5 \strokec5 apibanking\cf4 \strokec4 ;\cb1 \
\
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 java\cf6 \strokec6 .\cf5 \strokec5 security\cf6 \strokec6 .*\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 java\cf6 \strokec6 .\cf5 \strokec5 security\cf6 \strokec6 .\cf5 \strokec5 spec\cf6 \strokec6 .*\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 javax\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 Cipher\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 java\cf6 \strokec6 .\cf5 \strokec5 util\cf6 \strokec6 .\cf5 \strokec5 Base64\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 java\cf6 \strokec6 .\cf5 \strokec5 util\cf6 \strokec6 .\cf5 \strokec5 Collections\cf4 \strokec4 ;\cb1 \
\
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 javax\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 spec\cf6 \strokec6 .\cf5 \strokec5 PSource\cf4 \strokec4 ;\cb1 \
\
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 org\cf6 \strokec6 .\cf5 \strokec5 bouncycastle\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 BufferedBlockCipher\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 org\cf6 \strokec6 .\cf5 \strokec5 bouncycastle\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 InvalidCipherTextException\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 org\cf6 \strokec6 .\cf5 \strokec5 bouncycastle\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 engines\cf6 \strokec6 .\cf5 \strokec5 AESEngine\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 org\cf6 \strokec6 .\cf5 \strokec5 bouncycastle\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 modes\cf6 \strokec6 .\cf5 \strokec5 CFBBlockCipher\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 org\cf6 \strokec6 .\cf5 \strokec5 bouncycastle\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 params\cf6 \strokec6 .\cf5 \strokec5 KeyParameter\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 org\cf6 \strokec6 .\cf5 \strokec5 bouncycastle\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 params\cf6 \strokec6 .\cf5 \strokec5 ParametersWithIV\cf4 \strokec4 ;\cb1 \
\
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 jakarta\cf6 \strokec6 .\cf5 \strokec5 xml\cf6 \strokec6 .\cf5 \strokec5 bind\cf6 \strokec6 .\cf5 \strokec5 DatatypeConverter\cf4 \strokec4 ;\cb1 \
\
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 javax\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 spec\cf6 \strokec6 .\cf5 \strokec5 OAEPParameterSpec\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 java\cf6 \strokec6 .\cf5 \strokec5 util\cf6 \strokec6 .\cf5 \strokec5 HashMap\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 java\cf6 \strokec6 .\cf5 \strokec5 util\cf6 \strokec6 .\cf5 \strokec5 Map\cf4 \strokec4 ;\cb1 \
\
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 javax\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 BadPaddingException\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 javax\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 IllegalBlockSizeException\cf4 \strokec4 ;\cb1 \
\cf2 \cb3 \strokec2 import\cf4 \strokec4  \cf5 \strokec5 javax\cf6 \strokec6 .\cf5 \strokec5 crypto\cf6 \strokec6 .\cf5 \strokec5 NoSuchPaddingException\cf4 \strokec4 ;\cb1 \
\
\cf2 \cb3 \strokec2 public\cf4 \strokec4  \cf2 \strokec2 class\cf4 \strokec4  \cf5 \strokec5 NsdlResponseDecryptor\cf4 \strokec4  \{\cb1 \
\
\pard\pardeftab720\partightenfactor0
\cf4 \cb3   \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf2 \strokec2 final\cf4 \strokec4  \cf5 \strokec5 int\cf4 \strokec4  \cf7 \strokec7 PUBLIC_KEY_SIZE\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf8 \strokec8 294\cf4 \strokec4 ;\cb1 \
\cb3   \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf2 \strokec2 final\cf4 \strokec4  \cf5 \strokec5 int\cf4 \strokec4  \cf7 \strokec7 EID_SIZE\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf8 \strokec8 32\cf4 \strokec4 ;\cb1 \
\cb3   \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf2 \strokec2 final\cf4 \strokec4  \cf5 \strokec5 int\cf4 \strokec4  \cf7 \strokec7 SECRET_KEY_SIZE\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf8 \strokec8 256\cf4 \strokec4 ;\cb1 \
\cb3   \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf2 \strokec2 final\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf7 \strokec7 HEADER_DATA\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf9 \strokec9 "VERSION_1.0"\cf4 \strokec4 .\cf10 \strokec10 getBytes\cf4 \strokec4 ();\cb1 \
\
\cb3   \cf11 \strokec11 // ByteArraySpliter class\cf4 \cb1 \strokec4 \
\cb3   \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf2 \strokec2 class\cf4 \strokec4  \cf5 \strokec5 ByteArraySpliter\cf4 \strokec4  \{\cb1 \
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 final\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf7 \strokec7 headerVersion\cf4 \strokec4 ;\cb1 \
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 final\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf7 \strokec7 iv\cf4 \strokec4 ;\cb1 \
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 final\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf7 \strokec7 encryptedSecretKey\cf4 \strokec4 ;\cb1 \
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 final\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf7 \strokec7 encryptedData\cf4 \strokec4 ;\cb1 \
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 final\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf7 \strokec7 publicKeyData\cf4 \strokec4 ;\cb1 \
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf5 \strokec5 MessageDigest\cf4 \strokec4  \cf12 \strokec12 mgfMd\cf4 \strokec4 ;\cb1 \
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf5 \strokec5 MessageDigest\cf4 \strokec4  \cf12 \strokec12 md\cf4 \strokec4 ;\cb1 \
\
\cb3     \cf2 \strokec2 public\cf4 \strokec4  \cf10 \strokec10 ByteArraySpliter\cf4 \strokec4 (\cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 data\cf4 \strokec4 ) \cf2 \strokec2 throws\cf4 \strokec4  \cf5 \strokec5 Exception\cf4 \strokec4  \{\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 offset\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 ;\cb1 \
\cb3       \cf7 \strokec7 headerVersion\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf7 \strokec7 HEADER_DATA\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 ];\cb1 \
\cb3       \cf10 \strokec10 copyByteArray\cf4 \strokec4 (\cf12 \strokec12 data\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 , \cf7 \strokec7 headerVersion\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 , \cf7 \strokec7 headerVersion\cf4 \strokec4 );\cb1 \
\cb3       \cf12 \strokec12 offset\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 offset\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf7 \strokec7 HEADER_DATA\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 ;\cb1 \
\cb3       \cf7 \strokec7 publicKeyData\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf7 \strokec7 PUBLIC_KEY_SIZE\cf4 \strokec4 ];\cb1 \
\cb3       \cf10 \strokec10 copyByteArray\cf4 \strokec4 (\cf12 \strokec12 data\cf4 \strokec4 , \cf12 \strokec12 offset\cf4 \strokec4 , \cf7 \strokec7 publicKeyData\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 , \cf7 \strokec7 publicKeyData\cf4 \strokec4 );\cb1 \
\cb3       \cf12 \strokec12 offset\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 offset\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf7 \strokec7 PUBLIC_KEY_SIZE\cf4 \strokec4 ;\cb1 \
\cb3       \cf7 \strokec7 iv\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf7 \strokec7 EID_SIZE\cf4 \strokec4 ];\cb1 \
\cb3       \cf10 \strokec10 copyByteArray\cf4 \strokec4 (\cf12 \strokec12 data\cf4 \strokec4 , \cf12 \strokec12 offset\cf4 \strokec4 , \cf7 \strokec7 iv\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 , \cf7 \strokec7 iv\cf4 \strokec4 );\cb1 \
\cb3       \cf12 \strokec12 offset\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 offset\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf7 \strokec7 EID_SIZE\cf4 \strokec4 ;\cb1 \
\cb3       \cf7 \strokec7 encryptedSecretKey\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf7 \strokec7 SECRET_KEY_SIZE\cf4 \strokec4 ];\cb1 \
\cb3       \cf10 \strokec10 copyByteArray\cf4 \strokec4 (\cf12 \strokec12 data\cf4 \strokec4 , \cf12 \strokec12 offset\cf4 \strokec4 , \cf7 \strokec7 encryptedSecretKey\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 , \cf7 \strokec7 encryptedSecretKey\cf4 \strokec4 );\cb1 \
\cb3       \cf12 \strokec12 offset\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 offset\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf7 \strokec7 SECRET_KEY_SIZE\cf4 \strokec4 ;\cb1 \
\cb3       \cf7 \strokec7 encryptedData\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf12 \strokec12 data\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf12 \strokec12 offset\cf4 \strokec4 ];\cb1 \
\cb3       \cf10 \strokec10 copyByteArray\cf4 \strokec4 (\cf12 \strokec12 data\cf4 \strokec4 , \cf12 \strokec12 offset\cf4 \strokec4 , \cf7 \strokec7 encryptedData\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 , \cf7 \strokec7 encryptedData\cf4 \strokec4 );\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 public\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf10 \strokec10 getIv\cf4 \strokec4 () \{\cb1 \
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf7 \strokec7 iv\cf4 \strokec4 ;\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 public\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf10 \strokec10 getEncryptedSecretKey\cf4 \strokec4 () \{\cb1 \
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf7 \strokec7 encryptedSecretKey\cf4 \strokec4 ;\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 public\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf10 \strokec10 getEncryptedData\cf4 \strokec4 () \{\cb1 \
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf7 \strokec7 encryptedData\cf4 \strokec4 ;\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf11 \strokec11 // Method to print byte arrays as strings\cf4 \cb1 \strokec4 \
\cb3     \cf2 \strokec2 public\cf4 \strokec4  \cf5 \strokec5 String\cf4 \strokec4  \cf10 \strokec10 toString\cf4 \strokec4 () \{\cb1 \
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf9 \strokec9 "Header Version: "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 String\cf4 \strokec4 (\cf7 \strokec7 headerVersion\cf4 \strokec4 ) \cf6 \strokec6 +\cf4 \strokec4  \cf9 \strokec9 "\cf14 \strokec14 \\n\\n\\n\cf9 \strokec9 "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \cb1 \strokec4 \
\cb3           \cf9 \strokec9 "Public Key Data: "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf5 \strokec5 Base64\cf4 \strokec4 .\cf10 \strokec10 getEncoder\cf4 \strokec4 ().\cf10 \strokec10 encodeToString\cf4 \strokec4 (\cf7 \strokec7 publicKeyData\cf4 \strokec4 ) \cf6 \strokec6 +\cf4 \strokec4  \cf9 \strokec9 "\cf14 \strokec14 \\n\\n\\n\cf9 \strokec9 "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \cb1 \strokec4 \
\cb3           \cf9 \strokec9 "IV: "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf5 \strokec5 Base64\cf4 \strokec4 .\cf10 \strokec10 getEncoder\cf4 \strokec4 ().\cf10 \strokec10 encodeToString\cf4 \strokec4 (\cf7 \strokec7 iv\cf4 \strokec4 ) \cf6 \strokec6 +\cf4 \strokec4  \cf9 \strokec9 "\cf14 \strokec14 \\n\\n\\n\cf9 \strokec9 "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \cb1 \strokec4 \
\cb3           \cf9 \strokec9 "Encrypted Secret Key: "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf5 \strokec5 Base64\cf4 \strokec4 .\cf10 \strokec10 getEncoder\cf4 \strokec4 ().\cf10 \strokec10 encodeToString\cf4 \strokec4 (\cf7 \strokec7 encryptedSecretKey\cf4 \strokec4 ) \cf6 \strokec6 +\cf4 \strokec4  \cf9 \strokec9 "\cf14 \strokec14 \\n\\n\\n\cf9 \strokec9 "\cf4 \strokec4 ;\cb1 \
\cb3       \cf11 \strokec11 // "Encrypted Data: " + Base64.getEncoder().encodeToString(encryptedData);\cf4 \cb1 \strokec4 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf5 \strokec5 void\cf4 \strokec4  \cf10 \strokec10 copyByteArray\cf4 \strokec4 (\cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 src\cf4 \strokec4 , \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 offset\cf4 \strokec4 , \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 length\cf4 \strokec4 , \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 dest\cf4 \strokec4 ) \cf2 \strokec2 throws\cf4 \strokec4  \cf5 \strokec5 Exception\cf4 \strokec4  \{\cb1 \
\cb3       \cf13 \strokec13 try\cf4 \strokec4  \{\cb1 \
\cb3         \cf5 \strokec5 System\cf4 \strokec4 .\cf10 \strokec10 arraycopy\cf4 \strokec4 (\cf12 \strokec12 src\cf4 \strokec4 , \cf12 \strokec12 offset\cf4 \strokec4 , \cf12 \strokec12 dest\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 , \cf12 \strokec12 length\cf4 \strokec4 );\cb1 \
\cb3       \} \cf13 \strokec13 catch\cf4 \strokec4  (\cf5 \strokec5 Exception\cf4 \strokec4  \cf12 \strokec12 e\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf13 \strokec13 throw\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 Exception\cf4 \strokec4 (\cf9 \strokec9 "Decryption failed, Corrupted packet "\cf4 \strokec4 , \cf12 \strokec12 e\cf4 \strokec4 );\cb1 \
\cb3       \}\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf10 \strokec10 decryptSecretKeyData\cf4 \strokec4 (\cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 encryptedSecretKey\cf4 \strokec4 , \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 iv\cf4 \strokec4 , \cf5 \strokec5 PrivateKey\cf4 \strokec4  \cf12 \strokec12 privateKey\cf4 \strokec4 ) \cf2 \strokec2 throws\cf4 \strokec4  \cf5 \strokec5 Exception\cf4 \strokec4  \{\cb1 \
\
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 decryptedData\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf2 \strokec2 null\cf4 \strokec4 ;\cb1 \
\
\cb3       \cf12 \strokec12 decryptedData\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf10 \strokec10 rsaDecryptOaepSha256Mgf1Padding\cf4 \strokec4 (\cf12 \strokec12 encryptedSecretKey\cf4 \strokec4 , \cf12 \strokec12 privateKey\cf4 \strokec4 , \cf12 \strokec12 iv\cf4 \strokec4 );\cb1 \
\
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf12 \strokec12 decryptedData\cf4 \strokec4 ;\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 public\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf10 \strokec10 rsaDecryptOaepSha256Mgf1Padding\cf4 \strokec4 (\cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 cipherText\cf4 \strokec4 , \cf5 \strokec5 PrivateKey\cf4 \strokec4  \cf12 \strokec12 privKey\cf4 \strokec4 , \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 iv\cf4 \strokec4 )\cb1 \
\cb3         \cf2 \strokec2 throws\cf4 \strokec4  \cf5 \strokec5 NoSuchAlgorithmException\cf4 \strokec4 , \cf5 \strokec5 NoSuchPaddingException\cf4 \strokec4 , \cf5 \strokec5 InvalidKeyException\cf4 \strokec4 , \cf5 \strokec5 IllegalBlockSizeException\cf4 \strokec4 ,\cb1 \
\cb3         \cf5 \strokec5 InvalidAlgorithmParameterException\cf4 \strokec4 , \cf5 \strokec5 BadPaddingException\cf4 \strokec4  \{\cb1 \
\
\cb3       \cf11 \strokec11 // Define OAEP parameters\cf4 \cb1 \strokec4 \
\cb3       \cf5 \strokec5 PSource\cf4 \strokec4  \cf12 \strokec12 pSrc\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 PSource\cf4 \strokec4 .\cf10 \strokec10 PSpecified\cf4 \strokec4 (\cf12 \strokec12 iv\cf4 \strokec4 );\cb1 \
\cb3       \cf5 \strokec5 OAEPParameterSpec\cf4 \strokec4  \cf12 \strokec12 oaepParams\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 OAEPParameterSpec\cf4 \strokec4 (\cb1 \
\cb3           \cf9 \strokec9 "SHA-256"\cf4 \strokec4 , \cf11 \strokec11 // Hashing algorithm\cf4 \cb1 \strokec4 \
\cb3           \cf9 \strokec9 "MGF1"\cf4 \strokec4 , \cf11 \strokec11 // Mask generation function\cf4 \cb1 \strokec4 \
\cb3           \cf5 \strokec5 MGF1ParameterSpec\cf4 \strokec4 .\cf7 \strokec7 SHA256\cf4 \strokec4 , \cf11 \strokec11 // MGF1 uses SHA-256\cf4 \cb1 \strokec4 \
\cb3           \cf12 \strokec12 pSrc\cf4 \strokec4  \cf11 \strokec11 // PSource (with the iv as the label)\cf4 \cb1 \strokec4 \
\cb3       );\cb1 \
\
\cb3       \cf11 \strokec11 // Initialize Cipher with RSA/OAEP and SHA-256 padding\cf4 \cb1 \strokec4 \
\cb3       \cf5 \strokec5 Cipher\cf4 \strokec4  \cf12 \strokec12 cipher\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf5 \strokec5 Cipher\cf4 \strokec4 .\cf10 \strokec10 getInstance\cf4 \strokec4 (\cf9 \strokec9 "RSA/ECB/NoPadding"\cf4 \strokec4 );\cb1 \
\cb3       \cf12 \strokec12 cipher\cf4 \strokec4 .\cf10 \strokec10 init\cf4 \strokec4 (\cf5 \strokec5 Cipher\cf4 \strokec4 .\cf7 \strokec7 DECRYPT_MODE\cf4 \strokec4 , \cf12 \strokec12 privKey\cf4 \strokec4 );\cb1 \
\
\cb3       \cf11 \strokec11 // Perform decryption\cf4 \cb1 \strokec4 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 paddedPlainText\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 cipher\cf4 \strokec4 .\cf10 \strokec10 doFinal\cf4 \strokec4 (\cf12 \strokec12 cipherText\cf4 \strokec4 );\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 keyLength\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf8 \strokec8 2048\cf4 \strokec4 ;\cb1 \
\cb3       \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 paddedPlainText\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 <\cf4 \strokec4  (\cf12 \strokec12 keyLength\cf4 \strokec4  \cf6 \strokec6 /\cf4 \strokec4  \cf8 \strokec8 8\cf4 \strokec4 )) \{\cb1 \
\cb3         \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 tmp\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf12 \strokec12 keyLength\cf4 \strokec4  \cf6 \strokec6 /\cf4 \strokec4  \cf8 \strokec8 8\cf4 \strokec4 ];\cb1 \
\cb3         \cf5 \strokec5 System\cf4 \strokec4 .\cf10 \strokec10 arraycopy\cf4 \strokec4 (\cf12 \strokec12 paddedPlainText\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 , \cf12 \strokec12 tmp\cf4 \strokec4 , \cf12 \strokec12 tmp\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf12 \strokec12 paddedPlainText\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 , \cf12 \strokec12 paddedPlainText\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 );\cb1 \
\cb3         \cf12 \strokec12 paddedPlainText\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 tmp\cf4 \strokec4 ;\cb1 \
\cb3       \}\cb1 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 plainText\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf10 \strokec10 RSAPaddingInternal\cf4 \strokec4 (\cf12 \strokec12 oaepParams\cf4 \strokec4 , \cf12 \strokec12 paddedPlainText\cf4 \strokec4 );\cb1 \
\cb3       \cf11 \strokec11 // Convert the plainText bytes to a hex string and print it (optional)\cf4 \cb1 \strokec4 \
\
\cb3       \cf5 \strokec5 String\cf4 \strokec4  \cf12 \strokec12 hexPlainTextString\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 DatatypeConverter\cf4 \strokec4 .\cf10 \strokec10 printHexBinary\cf4 \strokec4 (\cf12 \strokec12 plainText\cf4 \strokec4 );\cb1 \
\
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 scretKey\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 DatatypeConverter\cf4 \strokec4 .\cf10 \strokec10 parseHexBinary\cf4 \strokec4 (\cf12 \strokec12 hexPlainTextString\cf4 \strokec4 );\cb1 \
\
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf12 \strokec12 scretKey\cf4 \strokec4 ;\cb1 \
\
\cb3     \}\cb1 \
\
\cb3     \cf11 \strokec11 // Helper method to convert the private key string (Base64 encoded) to a\cf4 \cb1 \strokec4 \
\cb3     \cf11 \strokec11 // PrivateKey object\cf4 \cb1 \strokec4 \
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf5 \strokec5 PrivateKey\cf4 \strokec4  \cf10 \strokec10 getPrivateKeyFromString\cf4 \strokec4 (\cf5 \strokec5 String\cf4 \strokec4  \cf12 \strokec12 privateKeyString\cf4 \strokec4 ) \cf2 \strokec2 throws\cf4 \strokec4  \cf5 \strokec5 Exception\cf4 \strokec4  \{\cb1 \
\cb3       \cf11 \strokec11 // Remove header/footer from PEM format if necessary\cf4 \cb1 \strokec4 \
\cb3       \cf5 \strokec5 String\cf4 \strokec4  \cf12 \strokec12 privateKeyPEM\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 privateKeyString\cf4 \cb1 \strokec4 \
\cb3           .\cf10 \strokec10 replace\cf4 \strokec4 (\cf9 \strokec9 "-----BEGIN PRIVATE KEY-----"\cf4 \strokec4 , \cf9 \strokec9 ""\cf4 \strokec4 )\cb1 \
\cb3           .\cf10 \strokec10 replace\cf4 \strokec4 (\cf9 \strokec9 "-----END PRIVATE KEY-----"\cf4 \strokec4 , \cf9 \strokec9 ""\cf4 \strokec4 )\cb1 \
\cb3           .\cf10 \strokec10 replaceAll\cf4 \strokec4 (\cf9 \strokec9 "\cf14 \strokec14 \\\\\cf9 \strokec9 s+"\cf4 \strokec4 , \cf9 \strokec9 ""\cf4 \strokec4 );\cb1 \
\
\cb3       \cf11 \strokec11 // Decode Base64 to byte array\cf4 \cb1 \strokec4 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 keyBytes\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf5 \strokec5 Base64\cf4 \strokec4 .\cf10 \strokec10 getDecoder\cf4 \strokec4 ().\cf10 \strokec10 decode\cf4 \strokec4 (\cf12 \strokec12 privateKeyPEM\cf4 \strokec4 );\cb1 \
\
\cb3       \cf11 \strokec11 // Create a KeyFactory for RSA\cf4 \cb1 \strokec4 \
\cb3       \cf5 \strokec5 KeyFactory\cf4 \strokec4  \cf12 \strokec12 keyFactory\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf5 \strokec5 KeyFactory\cf4 \strokec4 .\cf10 \strokec10 getInstance\cf4 \strokec4 (\cf9 \strokec9 "RSA"\cf4 \strokec4 );\cb1 \
\
\cb3       \cf11 \strokec11 // Generate the private key from the key specification\cf4 \cb1 \strokec4 \
\cb3       \cf5 \strokec5 PKCS8EncodedKeySpec\cf4 \strokec4  \cf12 \strokec12 keySpec\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 PKCS8EncodedKeySpec\cf4 \strokec4 (\cf12 \strokec12 keyBytes\cf4 \strokec4 );\cb1 \
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf12 \strokec12 keyFactory\cf4 \strokec4 .\cf10 \strokec10 generatePrivate\cf4 \strokec4 (\cf12 \strokec12 keySpec\cf4 \strokec4 );\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf10 \strokec10 decryptData\cf4 \strokec4 (\cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 encryptedData\cf4 \strokec4 , \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 eid\cf4 \strokec4 , \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 secretKey\cf4 \strokec4 ) \cf2 \strokec2 throws\cf4 \strokec4  \cf5 \strokec5 Exception\cf4 \strokec4  \{\cb1 \
\cb3       \cf13 \strokec13 try\cf4 \strokec4  \{\cb1 \
\cb3         \cf5 \strokec5 byte\cf4 \strokec4 [][] \cf12 \strokec12 iv\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf10 \strokec10 split\cf4 \strokec4 (\cf12 \strokec12 eid\cf4 \strokec4 , \cf8 \strokec8 16\cf4 \strokec4 );\cb1 \
\
\cb3         \cf5 \strokec5 BufferedBlockCipher\cf4 \strokec4  \cf12 \strokec12 cipher\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 BufferedBlockCipher\cf4 \strokec4 (\cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 CFBBlockCipher\cf4 \strokec4 (\cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 AESEngine\cf4 \strokec4 (), \cf8 \strokec8 128\cf4 \strokec4 ));\cb1 \
\cb3         \cf5 \strokec5 KeyParameter\cf4 \strokec4  \cf12 \strokec12 key\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 KeyParameter\cf4 \strokec4 (\cf12 \strokec12 secretKey\cf4 \strokec4 );\cb1 \
\
\cb3         \cf12 \strokec12 cipher\cf4 \strokec4 .\cf10 \strokec10 init\cf4 \strokec4 (\cf2 \strokec2 false\cf4 \strokec4 , \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 ParametersWithIV\cf4 \strokec4 (\cf12 \strokec12 key\cf4 \strokec4 , \cf12 \strokec12 iv\cf4 \strokec4 [\cf8 \strokec8 0\cf4 \strokec4 ]));\cb1 \
\
\cb3         \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 outputSize\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 cipher\cf4 \strokec4 .\cf10 \strokec10 getOutputSize\cf4 \strokec4 (\cf12 \strokec12 encryptedData\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 );\cb1 \
\
\cb3         \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 result\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf12 \strokec12 outputSize\cf4 \strokec4 ];\cb1 \
\cb3         \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 processLen\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 cipher\cf4 \strokec4 .\cf10 \strokec10 processBytes\cf4 \strokec4 (\cf12 \strokec12 encryptedData\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 , \cf12 \strokec12 encryptedData\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 , \cf12 \strokec12 result\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 );\cb1 \
\cb3         \cf12 \strokec12 cipher\cf4 \strokec4 .\cf10 \strokec10 doFinal\cf4 \strokec4 (\cf12 \strokec12 result\cf4 \strokec4 , \cf12 \strokec12 processLen\cf4 \strokec4 );\cb1 \
\cb3         \cf13 \strokec13 return\cf4 \strokec4  \cf12 \strokec12 result\cf4 \strokec4 ;\cb1 \
\cb3       \} \cf13 \strokec13 catch\cf4 \strokec4  (\cf5 \strokec5 InvalidCipherTextException\cf4 \strokec4  \cf12 \strokec12 txtExp\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf13 \strokec13 throw\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 Exception\cf4 \strokec4 (\cf9 \strokec9 "Decrypting data using AES failed"\cf4 \strokec4 , \cf12 \strokec12 txtExp\cf4 \strokec4 );\cb1 \
\cb3       \}\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 public\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf10 \strokec10 RSAPaddingInternal\cf4 \strokec4 (\cf5 \strokec5 OAEPParameterSpec\cf4 \strokec4  \cf12 \strokec12 spec\cf4 \strokec4 , \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 padded\cf4 \strokec4 )\cb1 \
\cb3         \cf2 \strokec2 throws\cf4 \strokec4  \cf5 \strokec5 InvalidAlgorithmParameterException\cf4 \strokec4 , \cf5 \strokec5 NoSuchAlgorithmException\cf4 \strokec4 , \cf5 \strokec5 InvalidKeyException\cf4 \strokec4 , \cf5 \strokec5 BadPaddingException\cf4 \strokec4  \{\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 paddedSize\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf8 \strokec8 256\cf4 \strokec4 ;\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 maxDataSize\cf4 \strokec4 ;\cb1 \
\cb3       \cf5 \strokec5 String\cf4 \strokec4  \cf12 \strokec12 mdName\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 spec\cf4 \strokec4 .\cf10 \strokec10 getDigestAlgorithm\cf4 \strokec4 ();\cb1 \
\cb3       \cf5 \strokec5 String\cf4 \strokec4  \cf12 \strokec12 mgfName\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 spec\cf4 \strokec4 .\cf10 \strokec10 getMGFAlgorithm\cf4 \strokec4 ();\cb1 \
\
\cb3       \cf13 \strokec13 if\cf4 \strokec4  (\cf6 \strokec6 !\cf12 \strokec12 mgfName\cf4 \strokec4 .\cf10 \strokec10 equalsIgnoreCase\cf4 \strokec4 (\cf9 \strokec9 "MGF1"\cf4 \strokec4 )) \{\cb1 \
\cb3         \cf13 \strokec13 throw\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 InvalidAlgorithmParameterException\cf4 \strokec4 (\cf9 \strokec9 "Unsupported MGF algo: "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf12 \strokec12 mgfName\cf4 \strokec4 );\cb1 \
\cb3       \}\cb1 \
\cb3       \cf5 \strokec5 String\cf4 \strokec4  \cf12 \strokec12 mgfMdName\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  ((\cf5 \strokec5 MGF1ParameterSpec\cf4 \strokec4 ) \cf12 \strokec12 spec\cf4 \strokec4 .\cf10 \strokec10 getMGFParameters\cf4 \strokec4 ()).\cf10 \strokec10 getDigestAlgorithm\cf4 \strokec4 ();\cb1 \
\cb3       \cf5 \strokec5 PSource\cf4 \strokec4  \cf12 \strokec12 pSrc\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 spec\cf4 \strokec4 .\cf10 \strokec10 getPSource\cf4 \strokec4 ();\cb1 \
\cb3       \cf5 \strokec5 String\cf4 \strokec4  \cf12 \strokec12 pSrcAlgo\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 pSrc\cf4 \strokec4 .\cf10 \strokec10 getAlgorithm\cf4 \strokec4 ();\cb1 \
\cb3       \cf13 \strokec13 if\cf4 \strokec4  (\cf6 \strokec6 !\cf12 \strokec12 pSrcAlgo\cf4 \strokec4 .\cf10 \strokec10 equalsIgnoreCase\cf4 \strokec4 (\cf9 \strokec9 "PSpecified"\cf4 \strokec4 )) \{\cb1 \
\cb3         \cf13 \strokec13 throw\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 InvalidAlgorithmParameterException\cf4 \strokec4 (\cf9 \strokec9 "Unsupported pSource algo: "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf12 \strokec12 pSrcAlgo\cf4 \strokec4 );\cb1 \
\cb3       \}\cb1 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 digestInput\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  ((\cf5 \strokec5 PSource\cf4 \strokec4 .\cf5 \strokec5 PSpecified\cf4 \strokec4 ) \cf12 \strokec12 pSrc\cf4 \strokec4 ).\cf10 \strokec10 getValue\cf4 \strokec4 ();\cb1 \
\cb3       \cf5 \strokec5 MessageDigest\cf4 \strokec4  \cf12 \strokec12 md\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf5 \strokec5 MessageDigest\cf4 \strokec4 .\cf10 \strokec10 getInstance\cf4 \strokec4 (\cf12 \strokec12 mdName\cf4 \strokec4 );\cb1 \
\cb3       \cf12 \strokec12 mgfMd\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf5 \strokec5 MessageDigest\cf4 \strokec4 .\cf10 \strokec10 getInstance\cf4 \strokec4 (\cf12 \strokec12 mgfMdName\cf4 \strokec4 );\cb1 \
\
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 lHash\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf10 \strokec10 getInitialHash\cf4 \strokec4 (\cf12 \strokec12 md\cf4 \strokec4 , \cf12 \strokec12 digestInput\cf4 \strokec4 );\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 digestLen\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 lHash\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 ;\cb1 \
\cb3       \cf12 \strokec12 maxDataSize\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 paddedSize\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf8 \strokec8 2\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf8 \strokec8 2\cf4 \strokec4  \cf6 \strokec6 *\cf4 \strokec4  \cf12 \strokec12 digestLen\cf4 \strokec4 ;\cb1 \
\cb3       \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 maxDataSize\cf4 \strokec4  \cf6 \strokec6 <=\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf13 \strokec13 throw\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 InvalidKeyException\cf4 \strokec4 (\cb1 \
\cb3             \cf9 \strokec9 "Key is too short for encryption using OAEPPadding"\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf9 \strokec9 " with "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf12 \strokec12 mdName\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf9 \strokec9 " and MGF1"\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf12 \strokec12 mgfMdName\cf4 \strokec4 );\cb1 \
\cb3       \}\cb1 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 EM\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 padded\cf4 \strokec4 ;\cb1 \
\cb3       \cf5 \strokec5 boolean\cf4 \strokec4  \cf12 \strokec12 bp\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf2 \strokec2 false\cf4 \strokec4 ;\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 hLen\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 lHash\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 ;\cb1 \
\cb3       \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 EM\cf4 \strokec4 [\cf8 \strokec8 0\cf4 \strokec4 ] \cf6 \strokec6 !=\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf12 \strokec12 bp\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf2 \strokec2 true\cf4 \strokec4 ;\cb1 \
\cb3       \}\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 seedStart\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf8 \strokec8 1\cf4 \strokec4 ;\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 seedLen\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 hLen\cf4 \strokec4 ;\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 dbStart\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 hLen\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf8 \strokec8 1\cf4 \strokec4 ;\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 dbLen\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 EM\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf12 \strokec12 dbStart\cf4 \strokec4 ;\cb1 \
\cb3       \cf10 \strokec10 mgf1internal\cf4 \strokec4 (\cf12 \strokec12 EM\cf4 \strokec4 , \cf12 \strokec12 dbStart\cf4 \strokec4 , \cf12 \strokec12 dbLen\cf4 \strokec4 , \cf12 \strokec12 EM\cf4 \strokec4 , \cf12 \strokec12 seedStart\cf4 \strokec4 , \cf12 \strokec12 seedLen\cf4 \strokec4 );\cb1 \
\cb3       \cf10 \strokec10 mgf1internal\cf4 \strokec4 (\cf12 \strokec12 EM\cf4 \strokec4 , \cf12 \strokec12 seedStart\cf4 \strokec4 , \cf12 \strokec12 seedLen\cf4 \strokec4 , \cf12 \strokec12 EM\cf4 \strokec4 , \cf12 \strokec12 dbStart\cf4 \strokec4 , \cf12 \strokec12 dbLen\cf4 \strokec4 );\cb1 \
\cb3       \cf11 \strokec11 // verify lHash == lHash'\cf4 \cb1 \strokec4 \
\cb3       \cf13 \strokec13 for\cf4 \strokec4  (\cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 i\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 ; \cf12 \strokec12 i\cf4 \strokec4  \cf6 \strokec6 <\cf4 \strokec4  \cf12 \strokec12 hLen\cf4 \strokec4 ; \cf12 \strokec12 i\cf6 \strokec6 ++\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 lHash\cf4 \strokec4 [\cf12 \strokec12 i\cf4 \strokec4 ] \cf6 \strokec6 !=\cf4 \strokec4  \cf12 \strokec12 EM\cf4 \strokec4 [\cf12 \strokec12 dbStart\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf12 \strokec12 i\cf4 \strokec4 ]) \{\cb1 \
\cb3           \cf12 \strokec12 bp\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf2 \strokec2 true\cf4 \strokec4 ;\cb1 \
\cb3         \}\cb1 \
\cb3       \}\cb1 \
\
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 padStart\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 dbStart\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf12 \strokec12 hLen\cf4 \strokec4 ;\cb1 \
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 onePos\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf6 \strokec6 -\cf8 \strokec8 1\cf4 \strokec4 ;\cb1 \
\
\cb3       \cf13 \strokec13 for\cf4 \strokec4  (\cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 i\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 padStart\cf4 \strokec4 ; \cf12 \strokec12 i\cf4 \strokec4  \cf6 \strokec6 <\cf4 \strokec4  \cf12 \strokec12 EM\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 ; \cf12 \strokec12 i\cf6 \strokec6 ++\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 value\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 EM\cf4 \strokec4 [\cf12 \strokec12 i\cf4 \strokec4 ];\cb1 \
\cb3         \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 onePos\cf4 \strokec4  \cf6 \strokec6 ==\cf4 \strokec4  \cf6 \strokec6 -\cf8 \strokec8 1\cf4 \strokec4 ) \{\cb1 \
\cb3           \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 value\cf4 \strokec4  \cf6 \strokec6 ==\cf4 \strokec4  \cf8 \strokec8 0x00\cf4 \strokec4 ) \{\cb1 \
\cb3             \cf11 \strokec11 // continue;\cf4 \cb1 \strokec4 \
\cb3           \} \cf13 \strokec13 else\cf4 \strokec4  \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 value\cf4 \strokec4  \cf6 \strokec6 ==\cf4 \strokec4  \cf8 \strokec8 0x01\cf4 \strokec4 ) \{\cb1 \
\cb3             \cf12 \strokec12 onePos\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 i\cf4 \strokec4 ;\cb1 \
\cb3           \} \cf13 \strokec13 else\cf4 \strokec4  \{ \cf11 \strokec11 // Anything other than \{0,1\} is bad.\cf4 \cb1 \strokec4 \
\cb3             \cf12 \strokec12 bp\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf2 \strokec2 true\cf4 \strokec4 ;\cb1 \
\cb3           \}\cb1 \
\cb3         \}\cb1 \
\cb3       \}\cb1 \
\
\cb3       \cf11 \strokec11 // We either ran off the rails or found something other than 0/1.\cf4 \cb1 \strokec4 \
\cb3       \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 onePos\cf4 \strokec4  \cf6 \strokec6 ==\cf4 \strokec4  \cf6 \strokec6 -\cf8 \strokec8 1\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf12 \strokec12 bp\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf2 \strokec2 true\cf4 \strokec4 ;\cb1 \
\cb3         \cf12 \strokec12 onePos\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 EM\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf8 \strokec8 1\cf4 \strokec4 ; \cf11 \strokec11 // Don't inadvertently return any data.\cf4 \cb1 \strokec4 \
\cb3       \}\cb1 \
\
\cb3       \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 mStart\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 onePos\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf8 \strokec8 1\cf4 \strokec4 ;\cb1 \
\
\cb3       \cf11 \strokec11 // copy useless padding array for a constant-time method\cf4 \cb1 \strokec4 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 tmp\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf12 \strokec12 mStart\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf12 \strokec12 padStart\cf4 \strokec4 ];\cb1 \
\cb3       \cf5 \strokec5 System\cf4 \strokec4 .\cf10 \strokec10 arraycopy\cf4 \strokec4 (\cf12 \strokec12 EM\cf4 \strokec4 , \cf12 \strokec12 padStart\cf4 \strokec4 , \cf12 \strokec12 tmp\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 , \cf12 \strokec12 tmp\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 );\cb1 \
\
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 m\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf12 \strokec12 EM\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf12 \strokec12 mStart\cf4 \strokec4 ];\cb1 \
\cb3       \cf5 \strokec5 System\cf4 \strokec4 .\cf10 \strokec10 arraycopy\cf4 \strokec4 (\cf12 \strokec12 EM\cf4 \strokec4 , \cf12 \strokec12 mStart\cf4 \strokec4 , \cf12 \strokec12 m\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 , \cf12 \strokec12 m\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 );\cb1 \
\
\cb3       \cf5 \strokec5 BadPaddingException\cf4 \strokec4  \cf12 \strokec12 bpe\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 BadPaddingException\cf4 \strokec4 (\cf9 \strokec9 "Decryption error"\cf4 \strokec4 );\cb1 \
\
\cb3       \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 bp\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf13 \strokec13 throw\cf4 \strokec4  \cf12 \strokec12 bpe\cf4 \strokec4 ;\cb1 \
\cb3       \} \cf13 \strokec13 else\cf4 \strokec4  \{\cb1 \
\cb3         \cf13 \strokec13 return\cf4 \strokec4  \cf12 \strokec12 m\cf4 \strokec4 ;\cb1 \
\cb3       \}\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf5 \strokec5 void\cf4 \strokec4  \cf10 \strokec10 mgf1internal\cf4 \strokec4 (\cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 seed\cf4 \strokec4 , \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 seedOfs\cf4 \strokec4 , \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 seedLen\cf4 \strokec4 , \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 out\cf4 \strokec4 , \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 outOfs\cf4 \strokec4 , \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 maskLen\cf4 \strokec4 )\cb1 \
\cb3         \cf2 \strokec2 throws\cf4 \strokec4  \cf5 \strokec5 BadPaddingException\cf4 \strokec4  \{\cb1 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 C\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf8 \strokec8 4\cf4 \strokec4 ]; \cf11 \strokec11 // 32 bit counter\cf4 \cb1 \strokec4 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 digest\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf12 \strokec12 mgfMd\cf4 \strokec4 .\cf10 \strokec10 getDigestLength\cf4 \strokec4 ()];\cb1 \
\
\cb3       \cf11 \strokec11 // System.out.println("MGF1 Process Digest Length " + digest.length + "\cf4 \cb1 \strokec4 \
\cb3       \cf11 \strokec11 // MaskLength " + maskLen ) ;\}\cf4 \cb1 \strokec4 \
\cb3       \cf13 \strokec13 while\cf4 \strokec4  (\cf12 \strokec12 maskLen\cf4 \strokec4  \cf6 \strokec6 >\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf12 \strokec12 mgfMd\cf4 \strokec4 .\cf10 \strokec10 update\cf4 \strokec4 (\cf12 \strokec12 seed\cf4 \strokec4 , \cf12 \strokec12 seedOfs\cf4 \strokec4 , \cf12 \strokec12 seedLen\cf4 \strokec4 );\cb1 \
\cb3         \cf12 \strokec12 mgfMd\cf4 \strokec4 .\cf10 \strokec10 update\cf4 \strokec4 (\cf12 \strokec12 C\cf4 \strokec4 );\cb1 \
\cb3         \cf13 \strokec13 try\cf4 \strokec4  \{\cb1 \
\cb3           \cf12 \strokec12 mgfMd\cf4 \strokec4 .\cf10 \strokec10 digest\cf4 \strokec4 (\cf12 \strokec12 digest\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 , \cf12 \strokec12 digest\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 );\cb1 \
\cb3         \} \cf13 \strokec13 catch\cf4 \strokec4  (\cf5 \strokec5 DigestException\cf4 \strokec4  \cf12 \strokec12 e\cf4 \strokec4 ) \{\cb1 \
\cb3           \cf11 \strokec11 // should never happen\cf4 \cb1 \strokec4 \
\cb3           \cf13 \strokec13 throw\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 BadPaddingException\cf4 \strokec4 (\cf12 \strokec12 e\cf4 \strokec4 .\cf10 \strokec10 toString\cf4 \strokec4 ());\cb1 \
\cb3         \}\cb1 \
\cb3         \cf13 \strokec13 for\cf4 \strokec4  (\cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 i\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 ; (\cf12 \strokec12 i\cf4 \strokec4  \cf6 \strokec6 <\cf4 \strokec4  \cf12 \strokec12 digest\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 ) \cf6 \strokec6 &&\cf4 \strokec4  (\cf12 \strokec12 maskLen\cf4 \strokec4  \cf6 \strokec6 >\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 ); \cf12 \strokec12 maskLen\cf6 \strokec6 --\cf4 \strokec4 ) \{\cb1 \
\cb3           \cf12 \strokec12 out\cf4 \strokec4 [\cf12 \strokec12 outOfs\cf6 \strokec6 ++\cf4 \strokec4 ] \cf6 \strokec6 ^=\cf4 \strokec4  \cf12 \strokec12 digest\cf4 \strokec4 [\cf12 \strokec12 i\cf6 \strokec6 ++\cf4 \strokec4 ];\cb1 \
\cb3         \}\cb1 \
\cb3         \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 maskLen\cf4 \strokec4  \cf6 \strokec6 >\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 ) \{\cb1 \
\cb3           \cf11 \strokec11 // increment counter\cf4 \cb1 \strokec4 \
\cb3           \cf13 \strokec13 for\cf4 \strokec4  (\cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 i\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 C\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf8 \strokec8 1\cf4 \strokec4 ; (\cf6 \strokec6 ++\cf12 \strokec12 C\cf4 \strokec4 [\cf12 \strokec12 i\cf4 \strokec4 ] \cf6 \strokec6 ==\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 ) \cf6 \strokec6 &&\cf4 \strokec4  (\cf12 \strokec12 i\cf4 \strokec4  \cf6 \strokec6 >\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 ); \cf12 \strokec12 i\cf6 \strokec6 --\cf4 \strokec4 ) \{\cb1 \
\cb3             \cf11 \strokec11 // empty\cf4 \cb1 \strokec4 \
\cb3           \}\cb1 \
\cb3         \}\cb1 \
\cb3       \}\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf10 \strokec10 getInitialHash\cf4 \strokec4 (\cf5 \strokec5 MessageDigest\cf4 \strokec4  \cf12 \strokec12 md\cf4 \strokec4 ,\cb1 \
\cb3         \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 digestInput\cf4 \strokec4 ) \{\cb1 \
\cb3       \cf5 \strokec5 Map\cf4 \strokec4 <\cf5 \strokec5 String\cf4 \strokec4 , \cf5 \strokec5 byte\cf4 \strokec4 []> \cf12 \strokec12 emptyHashes\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf5 \strokec5 Collections\cf4 \strokec4 .\cf10 \strokec10 synchronizedMap\cf4 \strokec4 (\cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 HashMap\cf4 \strokec4 <\cf5 \strokec5 String\cf4 \strokec4 , \cf5 \strokec5 byte\cf4 \strokec4 []>());\cb1 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 result\cf4 \strokec4 ;\cb1 \
\cb3       \cf13 \strokec13 if\cf4 \strokec4  ((\cf12 \strokec12 digestInput\cf4 \strokec4  \cf6 \strokec6 ==\cf4 \strokec4  \cf2 \strokec2 null\cf4 \strokec4 ) \cf6 \strokec6 ||\cf4 \strokec4  (\cf12 \strokec12 digestInput\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 ==\cf4 \strokec4  \cf8 \strokec8 0\cf4 \strokec4 )) \{\cb1 \
\cb3         \cf5 \strokec5 String\cf4 \strokec4  \cf12 \strokec12 digestName\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 md\cf4 \strokec4 .\cf10 \strokec10 getAlgorithm\cf4 \strokec4 ();\cb1 \
\cb3         \cf12 \strokec12 result\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 emptyHashes\cf4 \strokec4 .\cf10 \strokec10 get\cf4 \strokec4 (\cf12 \strokec12 digestName\cf4 \strokec4 );\cb1 \
\cb3         \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 result\cf4 \strokec4  \cf6 \strokec6 ==\cf4 \strokec4  \cf2 \strokec2 null\cf4 \strokec4 ) \{\cb1 \
\cb3           \cf12 \strokec12 result\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 md\cf4 \strokec4 .\cf10 \strokec10 digest\cf4 \strokec4 ();\cb1 \
\cb3           \cf12 \strokec12 emptyHashes\cf4 \strokec4 .\cf10 \strokec10 put\cf4 \strokec4 (\cf12 \strokec12 digestName\cf4 \strokec4 , \cf12 \strokec12 result\cf4 \strokec4 );\cb1 \
\cb3         \}\cb1 \
\cb3       \} \cf13 \strokec13 else\cf4 \strokec4  \{\cb1 \
\cb3         \cf12 \strokec12 result\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 md\cf4 \strokec4 .\cf10 \strokec10 digest\cf4 \strokec4 (\cf12 \strokec12 digestInput\cf4 \strokec4 );\cb1 \
\cb3       \}\cb1 \
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf12 \strokec12 result\cf4 \strokec4 ;\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [][] \cf10 \strokec10 split\cf4 \strokec4 (\cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 src\cf4 \strokec4 , \cf5 \strokec5 int\cf4 \strokec4  \cf12 \strokec12 n\cf4 \strokec4 ) \{\cb1 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 l\cf4 \strokec4 , \cf12 \strokec12 r\cf4 \strokec4 ;\cb1 \
\cb3       \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 src\cf4 \strokec4  \cf6 \strokec6 ==\cf4 \strokec4  \cf2 \strokec2 null\cf4 \strokec4  \cf6 \strokec6 ||\cf4 \strokec4  \cf12 \strokec12 src\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 <=\cf4 \strokec4  \cf12 \strokec12 n\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf12 \strokec12 l\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 src\cf4 \strokec4 ;\cb1 \
\cb3         \cf12 \strokec12 r\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf8 \strokec8 0\cf4 \strokec4 ];\cb1 \
\cb3       \} \cf13 \strokec13 else\cf4 \strokec4  \{\cb1 \
\cb3         \cf12 \strokec12 l\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf12 \strokec12 n\cf4 \strokec4 ];\cb1 \
\cb3         \cf12 \strokec12 r\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf12 \strokec12 src\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf12 \strokec12 n\cf4 \strokec4 ];\cb1 \
\cb3         \cf5 \strokec5 System\cf4 \strokec4 .\cf10 \strokec10 arraycopy\cf4 \strokec4 (\cf12 \strokec12 src\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 , \cf12 \strokec12 l\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 , \cf12 \strokec12 n\cf4 \strokec4 );\cb1 \
\cb3         \cf5 \strokec5 System\cf4 \strokec4 .\cf10 \strokec10 arraycopy\cf4 \strokec4 (\cf12 \strokec12 src\cf4 \strokec4 , \cf12 \strokec12 n\cf4 \strokec4 , \cf12 \strokec12 r\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 , \cf12 \strokec12 r\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 );\cb1 \
\cb3       \}\cb1 \
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [][] \{ \cf12 \strokec12 l\cf4 \strokec4 , \cf12 \strokec12 r\cf4 \strokec4  \};\cb1 \
\cb3     \}\cb1 \
\
\cb3     \cf2 \strokec2 private\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [] \cf10 \strokec10 trimHMAC\cf4 \strokec4 (\cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 decryptedText\cf4 \strokec4 ) \{\cb1 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 actualText\cf4 \strokec4 ;\cb1 \
\cb3       \cf13 \strokec13 if\cf4 \strokec4  (\cf12 \strokec12 decryptedText\cf4 \strokec4  \cf6 \strokec6 ==\cf4 \strokec4  \cf2 \strokec2 null\cf4 \strokec4  \cf6 \strokec6 ||\cf4 \strokec4  \cf12 \strokec12 decryptedText\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 <=\cf4 \strokec4  \cf8 \strokec8 32\cf4 \strokec4 ) \{\cb1 \
\cb3         \cf12 \strokec12 actualText\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf8 \strokec8 0\cf4 \strokec4 ];\cb1 \
\cb3       \} \cf13 \strokec13 else\cf4 \strokec4  \{\cb1 \
\cb3         \cf12 \strokec12 actualText\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf5 \strokec5 byte\cf4 \strokec4 [\cf12 \strokec12 decryptedText\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4  \cf6 \strokec6 -\cf4 \strokec4  \cf8 \strokec8 32\cf4 \strokec4 ];\cb1 \
\cb3         \cf5 \strokec5 System\cf4 \strokec4 .\cf10 \strokec10 arraycopy\cf4 \strokec4 (\cf12 \strokec12 decryptedText\cf4 \strokec4 , \cf8 \strokec8 32\cf4 \strokec4 , \cf12 \strokec12 actualText\cf4 \strokec4 , \cf8 \strokec8 0\cf4 \strokec4 ,\cb1 \
\cb3             \cf12 \strokec12 actualText\cf4 \strokec4 .\cf7 \strokec7 length\cf4 \strokec4 );\cb1 \
\cb3       \}\cb1 \
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf12 \strokec12 actualText\cf4 \strokec4 ;\cb1 \
\cb3     \}\cb1 \
\cb3     \cf2 \strokec2 private\cf4 \strokec4   \cf5 \strokec5 KeyStore\cf4 \strokec4  \cf10 \strokec10 createHSMKeyStore\cf4 \strokec4 () \cf2 \strokec2 throws\cf4 \strokec4  \cf5 \strokec5 Exception\cf4 \strokec4  \{\cb1 \
\cb3       \cf11 \strokec11 // cfg file path to be configured\cf4 \cb1 \strokec4 \
\cb3       \cf5 \strokec5 String\cf4 \strokec4  \cf12 \strokec12 cfgPath\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf9 \strokec9 "F:\cf14 \strokec14 \\\\\cf9 \strokec9 ApiBanking\cf14 \strokec14 \\\\\cf9 \strokec9 HSM\cf14 \strokec14 \\\\\cf9 \strokec9 pkcs11.cfg"\cf4 \strokec4 ;\cb1 \
\cb3   \cb1 \
\cb3       \cf5 \strokec5 Provider\cf4 \strokec4  \cf12 \strokec12 provider\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf5 \strokec5 Security\cf4 \strokec4 .\cf10 \strokec10 getProvider\cf4 \strokec4 (\cf9 \strokec9 "SunPKCS11"\cf4 \strokec4 );\cb1 \
\cb3       \cf5 \strokec5 Provider\cf4 \strokec4  \cf12 \strokec12 newpProvider\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 provider\cf4 \strokec4 .\cf10 \strokec10 configure\cf4 \strokec4 (\cf12 \strokec12 cfgPath\cf4 \strokec4 );\cb1 \
\cb3       \cf5 \strokec5 Security\cf4 \strokec4 .\cf10 \strokec10 addProvider\cf4 \strokec4 (\cf12 \strokec12 newpProvider\cf4 \strokec4 );\cb1 \
\cb3      \cf5 \strokec5 System\cf4 \strokec4 .\cf7 \strokec7 out\cf4 \strokec4 .\cf10 \strokec10 println\cf4 \strokec4 (\cf9 \strokec9 "-------------PKCS11 provider loaded: "\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf12 \strokec12 newpProvider\cf4 \strokec4 .\cf10 \strokec10 getName\cf4 \strokec4 () \cf6 \strokec6 +\cf4 \strokec4  \cf9 \strokec9 "-------------------"\cf4 \strokec4 ); \cb1 \
\cb3       \cf5 \strokec5 KeyStore\cf4 \strokec4  \cf12 \strokec12 keystore\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf5 \strokec5 KeyStore\cf4 \strokec4 .\cf10 \strokec10 getInstance\cf4 \strokec4 (\cf9 \strokec9 "pkcs11"\cf4 \strokec4 , \cf12 \strokec12 newpProvider\cf4 \strokec4 );\cb1 \
\cb3       \cf5 \strokec5 System\cf4 \strokec4 .\cf7 \strokec7 out\cf4 \strokec4 .\cf10 \strokec10 println\cf4 \strokec4 (\cf9 \strokec9 "---------------- KeyStore Created:"\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf12 \strokec12 keystore\cf4 \strokec4 .\cf10 \strokec10 toString\cf4 \strokec4 () \cf6 \strokec6 +\cf4 \strokec4  \cf9 \strokec9 " -------------------"\cf4 \strokec4 );\cb1 \
\cb3      \cf12 \strokec12 keystore\cf4 \strokec4 .\cf10 \strokec10 load\cf4 \strokec4 (\cf2 \strokec2 null\cf4 \strokec4 , \cf9 \strokec9 "123456"\cf4 \strokec4 .\cf10 \strokec10 toCharArray\cf4 \strokec4 ());\cb1 \
\cb3       \cf5 \strokec5 System\cf4 \strokec4 .\cf7 \strokec7 out\cf4 \strokec4 .\cf10 \strokec10 println\cf4 \strokec4 (\cf9 \strokec9 " -----------------Successfully Loaded Keystore-------------------"\cf4 \strokec4 );\cb1 \
\cb3       \cf13 \strokec13 return\cf4 \strokec4  \cf12 \strokec12 keystore\cf4 \strokec4 ;\cb1 \
\cb3   \cb1 \
\cb3     \}\cb1 \
\cb3   \}\cb1 \
\
\cb3   \cf2 \strokec2 public\cf4 \strokec4  \cf2 \strokec2 static\cf4 \strokec4  \cf5 \strokec5 void\cf4 \strokec4  \cf10 \strokec10 main\cf4 \strokec4 (\cf5 \strokec5 String\cf4 \strokec4 [] \cf12 \strokec12 args\cf4 \strokec4 ) \{\cb1 \
\cb3     \cf5 \strokec5 String\cf4 \strokec4  \cf12 \strokec12 request\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf9 \strokec9 "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"\cf4 \strokec4 ;\cb1 \
\
\cb3     \cf13 \strokec13 try\cf4 \strokec4  \{\cb1 \
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 requestData\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf5 \strokec5 Base64\cf4 \strokec4 .\cf10 \strokec10 getDecoder\cf4 \strokec4 ().\cf10 \strokec10 decode\cf4 \strokec4 (\cf12 \strokec12 request\cf4 \strokec4 );\cb1 \
\cb3       \cf5 \strokec5 ByteArraySpliter\cf4 \strokec4  \cf12 \strokec12 spliter\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 ByteArraySpliter\cf4 \strokec4 (\cf12 \strokec12 requestData\cf4 \strokec4 );\cb1 \
\
\cb3       \cf5 \strokec5 System\cf4 \strokec4 .\cf7 \strokec7 out\cf4 \strokec4 .\cf10 \strokec10 println\cf4 \strokec4 (\cf12 \strokec12 spliter\cf4 \strokec4 .\cf10 \strokec10 toString\cf4 \strokec4 ());\cb1 \
\pard\pardeftab720\partightenfactor0
\cf5 \cb3 \strokec5 KeyStore\cf4 \strokec4  \cf12 \strokec12 keyStore\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 spliter\cf4 \strokec4 .\cf10 \strokec10 createHSMKeyStore\cf4 \strokec4 ();\cb1 \
\pard\pardeftab720\partightenfactor0
\cf4 \cb3       \cf5 \strokec5 PrivateKey\cf4 \strokec4  \cf12 \strokec12 privateKey\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  (\cf5 \strokec5 PrivateKey\cf4 \strokec4 ) \cf12 \strokec12 keyStore\cf4 \strokec4 .\cf10 \strokec10 getKey\cf4 \strokec4 (\cf9 \strokec9 "hdfcnsdl"\cf4 \strokec4 , \cf9 \strokec9 "123456"\cf4 \strokec4 .\cf10 \strokec10 toCharArray\cf4 \strokec4 ()); \cb1 \
\cb3      \cf11 \strokec11 // PrivateKey privateKeyData = spliter.getPrivateKeyFromString(privateKey);\cf4 \cb1 \strokec4 \
\
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 decryptedSecretKey\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 spliter\cf4 \strokec4 .\cf10 \strokec10 decryptSecretKeyData\cf4 \strokec4 (\cf12 \strokec12 spliter\cf4 \strokec4 .\cf7 \strokec7 encryptedSecretKey\cf4 \strokec4 , \cf12 \strokec12 spliter\cf4 \strokec4 .\cf7 \strokec7 iv\cf4 \strokec4 , \cf12 \strokec12 privateKey\cf4 \strokec4 );\cb1 \
\
\cb3       \cf5 \strokec5 System\cf4 \strokec4 .\cf7 \strokec7 out\cf4 \strokec4 .\cf10 \strokec10 println\cf4 \strokec4 (\cf9 \strokec9 "Decrypted Secret key:"\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf12 \strokec12 decryptedSecretKey\cf4 \strokec4 );\cb1 \
\
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 decr\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 spliter\cf4 \strokec4 .\cf10 \strokec10 decryptData\cf4 \strokec4 (\cf12 \strokec12 spliter\cf4 \strokec4 .\cf10 \strokec10 getEncryptedData\cf4 \strokec4 (), \cf12 \strokec12 spliter\cf4 \strokec4 .\cf7 \strokec7 iv\cf4 \strokec4 , \cf12 \strokec12 decryptedSecretKey\cf4 \strokec4 );\cb1 \
\
\cb3       \cf5 \strokec5 byte\cf4 \strokec4 [] \cf12 \strokec12 text\cf4 \strokec4  \cf6 \strokec6 =\cf4 \strokec4  \cf12 \strokec12 spliter\cf4 \strokec4 .\cf10 \strokec10 trimHMAC\cf4 \strokec4 (\cf12 \strokec12 decr\cf4 \strokec4 );\cb1 \
\
\cb3       \cf5 \strokec5 System\cf4 \strokec4 .\cf7 \strokec7 out\cf4 \strokec4 .\cf10 \strokec10 println\cf4 \strokec4 (\cf9 \strokec9 "Actual Text is --->"\cf4 \strokec4  \cf6 \strokec6 +\cf4 \strokec4  \cf13 \strokec13 new\cf4 \strokec4  \cf10 \strokec10 String\cf4 \strokec4 (\cf12 \strokec12 text\cf4 \strokec4 ));\cb1 \
\
\cb3     \} \cf13 \strokec13 catch\cf4 \strokec4  (\cf5 \strokec5 Exception\cf4 \strokec4  \cf12 \strokec12 e\cf4 \strokec4 ) \{\cb1 \
\cb3       \cf12 \strokec12 e\cf4 \strokec4 .\cf10 \strokec10 printStackTrace\cf4 \strokec4 ();\cb1 \
\cb3     \}\cb1 \
\cb3   \}\cb1 \
\cb3 \}\cb1 \
}