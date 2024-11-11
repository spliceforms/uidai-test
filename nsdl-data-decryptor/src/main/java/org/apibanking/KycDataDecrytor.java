package org.apibanking;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Collections;

import javax.crypto.spec.PSource;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import jakarta.xml.bind.DatatypeConverter;

import javax.crypto.spec.OAEPParameterSpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class KycDataDecrytor {

  private static final int PUBLIC_KEY_SIZE = 294;
  private static final int EID_SIZE = 32;
  private static final int SECRET_KEY_SIZE = 256;
  private static final byte[] HEADER_DATA = "VERSION_1.0".getBytes();

  // ByteArraySpliter class
  private static class ByteArraySpliter {
    private final byte[] headerVersion;
    private final byte[] iv;
    private final byte[] encryptedSecretKey;
    private final byte[] encryptedData;
    private final byte[] publicKeyData;
    private static MessageDigest mgfMd;
    private static MessageDigest md;

    public ByteArraySpliter(byte[] data) throws Exception {
      int offset = 0;
      headerVersion = new byte[HEADER_DATA.length];
      copyByteArray(data, 0, headerVersion.length, headerVersion);
      offset = offset + HEADER_DATA.length;
      publicKeyData = new byte[PUBLIC_KEY_SIZE];
      copyByteArray(data, offset, publicKeyData.length, publicKeyData);
      offset = offset + PUBLIC_KEY_SIZE;
      iv = new byte[EID_SIZE];
      copyByteArray(data, offset, iv.length, iv);
      offset = offset + EID_SIZE;
      encryptedSecretKey = new byte[SECRET_KEY_SIZE];
      copyByteArray(data, offset, encryptedSecretKey.length, encryptedSecretKey);
      offset = offset + SECRET_KEY_SIZE;
      encryptedData = new byte[data.length - offset];
      copyByteArray(data, offset, encryptedData.length, encryptedData);
    }

    public byte[] getIv() {
      return iv;
    }

    public byte[] getEncryptedSecretKey() {
      return encryptedSecretKey;
    }

    public byte[] getEncryptedData() {
      return encryptedData;
    }

    // Method to print byte arrays as strings
    public String toString() {
      return "Header Version: " + new String(headerVersion) + "\n\n\n" +
          "Public Key Data: " + Base64.getEncoder().encodeToString(publicKeyData) + "\n\n\n" +
          "IV: " + Base64.getEncoder().encodeToString(iv) + "\n\n\n" +
          "Encrypted Secret Key: " + Base64.getEncoder().encodeToString(encryptedSecretKey) + "\n\n\n";
      // "Encrypted Data: " + Base64.getEncoder().encodeToString(encryptedData);
    }

    private void copyByteArray(byte[] src, int offset, int length, byte[] dest) throws Exception {
      try {
        System.arraycopy(src, offset, dest, 0, length);
      } catch (Exception e) {
        throw new Exception("Decryption failed, Corrupted packet ", e);
      }
    }

    private byte[] decryptSecretKeyData(byte[] encryptedSecretKey, byte[] iv, PrivateKey privateKey) throws Exception {

      byte[] decryptedData = null;

      decryptedData = rsaDecryptOaepSha256Mgf1Padding(encryptedSecretKey, privateKey, iv);

      return decryptedData;
    }

    public byte[] rsaDecryptOaepSha256Mgf1Padding(byte[] cipherText, PrivateKey privKey, byte[] iv)
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
        InvalidAlgorithmParameterException, BadPaddingException {

      // Define OAEP parameters
      PSource pSrc = new PSource.PSpecified(iv);
      OAEPParameterSpec oaepParams = new OAEPParameterSpec(
          "SHA-256", // Hashing algorithm
          "MGF1", // Mask generation function
          MGF1ParameterSpec.SHA256, // MGF1 uses SHA-256
          pSrc // PSource (with the iv as the label)
      );

      // Initialize Cipher with RSA/OAEP and SHA-256 padding
      Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, privKey);

      // Perform decryption
      byte[] paddedPlainText = cipher.doFinal(cipherText);
      int keyLength = 2048;
      if (paddedPlainText.length < (keyLength / 8)) {
        byte[] tmp = new byte[keyLength / 8];
        System.arraycopy(paddedPlainText, 0, tmp, tmp.length - paddedPlainText.length, paddedPlainText.length);
        paddedPlainText = tmp;
      }
      byte[] plainText = RSAPaddingInternal(oaepParams, paddedPlainText);
      // Convert the plainText bytes to a hex string and print it (optional)

      String hexPlainTextString = DatatypeConverter.printHexBinary(plainText);

      byte[] scretKey = DatatypeConverter.parseHexBinary(hexPlainTextString);

      return scretKey;

    }

    // Helper method to convert the private key string (Base64 encoded) to a
    // PrivateKey object
    private PrivateKey getPrivateKeyFromString(String privateKeyString) throws Exception {
      // Remove header/footer from PEM format if necessary
      String privateKeyPEM = privateKeyString
          .replace("-----BEGIN PRIVATE KEY-----", "")
          .replace("-----END PRIVATE KEY-----", "")
          .replaceAll("\\s+", "");

      // Decode Base64 to byte array
      byte[] keyBytes = Base64.getDecoder().decode(privateKeyPEM);

      // Create a KeyFactory for RSA
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");

      // Generate the private key from the key specification
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
      return keyFactory.generatePrivate(keySpec);
    }

    private byte[] decryptData(byte[] encryptedData, byte[] eid, byte[] secretKey) throws Exception {
      try {
        byte[][] iv = split(eid, 16);

        BufferedBlockCipher cipher = new BufferedBlockCipher(new CFBBlockCipher(new AESEngine(), 128));
        KeyParameter key = new KeyParameter(secretKey);

        cipher.init(false, new ParametersWithIV(key, iv[0]));

        int outputSize = cipher.getOutputSize(encryptedData.length);

        byte[] result = new byte[outputSize];
        int processLen = cipher.processBytes(encryptedData, 0, encryptedData.length, result, 0);
        cipher.doFinal(result, processLen);
        return result;
      } catch (InvalidCipherTextException txtExp) {
        throw new Exception("Decrypting data using AES failed", txtExp);
      }
    }

    public static byte[] RSAPaddingInternal(OAEPParameterSpec spec, byte[] padded)
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException {
      int paddedSize = 256;
      int maxDataSize;
      String mdName = spec.getDigestAlgorithm();
      String mgfName = spec.getMGFAlgorithm();

      if (!mgfName.equalsIgnoreCase("MGF1")) {
        throw new InvalidAlgorithmParameterException("Unsupported MGF algo: " + mgfName);
      }
      String mgfMdName = ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm();
      PSource pSrc = spec.getPSource();
      String pSrcAlgo = pSrc.getAlgorithm();
      if (!pSrcAlgo.equalsIgnoreCase("PSpecified")) {
        throw new InvalidAlgorithmParameterException("Unsupported pSource algo: " + pSrcAlgo);
      }
      byte[] digestInput = ((PSource.PSpecified) pSrc).getValue();
      MessageDigest md = MessageDigest.getInstance(mdName);
      mgfMd = MessageDigest.getInstance(mgfMdName);

      byte[] lHash = getInitialHash(md, digestInput);
      int digestLen = lHash.length;
      maxDataSize = paddedSize - 2 - 2 * digestLen;
      if (maxDataSize <= 0) {
        throw new InvalidKeyException(
            "Key is too short for encryption using OAEPPadding" + " with " + mdName + " and MGF1" + mgfMdName);
      }
      byte[] EM = padded;
      boolean bp = false;
      int hLen = lHash.length;
      if (EM[0] != 0) {
        bp = true;
      }
      int seedStart = 1;
      int seedLen = hLen;
      int dbStart = hLen + 1;
      int dbLen = EM.length - dbStart;
      mgf1internal(EM, dbStart, dbLen, EM, seedStart, seedLen);
      mgf1internal(EM, seedStart, seedLen, EM, dbStart, dbLen);
      // verify lHash == lHash'
      for (int i = 0; i < hLen; i++) {
        if (lHash[i] != EM[dbStart + i]) {
          bp = true;
        }
      }

      int padStart = dbStart + hLen;
      int onePos = -1;

      for (int i = padStart; i < EM.length; i++) {
        int value = EM[i];
        if (onePos == -1) {
          if (value == 0x00) {
            // continue;
          } else if (value == 0x01) {
            onePos = i;
          } else { // Anything other than {0,1} is bad.
            bp = true;
          }
        }
      }

      // We either ran off the rails or found something other than 0/1.
      if (onePos == -1) {
        bp = true;
        onePos = EM.length - 1; // Don't inadvertently return any data.
      }

      int mStart = onePos + 1;

      // copy useless padding array for a constant-time method
      byte[] tmp = new byte[mStart - padStart];
      System.arraycopy(EM, padStart, tmp, 0, tmp.length);

      byte[] m = new byte[EM.length - mStart];
      System.arraycopy(EM, mStart, m, 0, m.length);

      BadPaddingException bpe = new BadPaddingException("Decryption error");

      if (bp) {
        throw bpe;
      } else {
        return m;
      }
    }

    private static void mgf1internal(byte[] seed, int seedOfs, int seedLen, byte[] out, int outOfs, int maskLen)
        throws BadPaddingException {
      byte[] C = new byte[4]; // 32 bit counter
      byte[] digest = new byte[mgfMd.getDigestLength()];

      // System.out.println("MGF1 Process Digest Length " + digest.length + "
      // MaskLength " + maskLen ) ;}
      while (maskLen > 0) {
        mgfMd.update(seed, seedOfs, seedLen);
        mgfMd.update(C);
        try {
          mgfMd.digest(digest, 0, digest.length);
        } catch (DigestException e) {
          // should never happen
          throw new BadPaddingException(e.toString());
        }
        for (int i = 0; (i < digest.length) && (maskLen > 0); maskLen--) {
          out[outOfs++] ^= digest[i++];
        }
        if (maskLen > 0) {
          // increment counter
          for (int i = C.length - 1; (++C[i] == 0) && (i > 0); i--) {
            // empty
          }
        }
      }
    }

    private static byte[] getInitialHash(MessageDigest md,
        byte[] digestInput) {
      Map<String, byte[]> emptyHashes = Collections.synchronizedMap(new HashMap<String, byte[]>());
      byte[] result;
      if ((digestInput == null) || (digestInput.length == 0)) {
        String digestName = md.getAlgorithm();
        result = emptyHashes.get(digestName);
        if (result == null) {
          result = md.digest();
          emptyHashes.put(digestName, result);
        }
      } else {
        result = md.digest(digestInput);
      }
      return result;
    }

    private byte[][] split(byte[] src, int n) {
      byte[] l, r;
      if (src == null || src.length <= n) {
        l = src;
        r = new byte[0];
      } else {
        l = new byte[n];
        r = new byte[src.length - n];
        System.arraycopy(src, 0, l, 0, n);
        System.arraycopy(src, n, r, 0, r.length);
      }
      return new byte[][] { l, r };
    }

    private byte[] trimHMAC(byte[] decryptedText) {
      byte[] actualText;
      if (decryptedText == null || decryptedText.length <= 32) {
        actualText = new byte[0];
      } else {
        actualText = new byte[decryptedText.length - 32];
        System.arraycopy(decryptedText, 32, actualText, 0,
            actualText.length);
      }
      return actualText;
    }
  }

  public static void main(String[] args) {
    String request1 = "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";

    String privateKey = """
        //Enter Private key here
                """;
    try {
      File npciRespXml = new File("NpciResponse.xml");
      // Create a DocumentBuilderFactory and DocumentBuilder
      DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
      DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

      // Parse the XML file and get the Document object
      Document doc = dBuilder.parse(npciRespXml);
      doc.getDocumentElement().normalize();

      Node kycRes = doc.getElementsByTagName("kycRes").item(0);
      String request = kycRes.getTextContent();
      byte[] requestData = Base64.getDecoder().decode(request);
      ByteArraySpliter spliter = new ByteArraySpliter(requestData);

      System.out.println(spliter.toString());

      PrivateKey privateKeyData = spliter.getPrivateKeyFromString(privateKey);

      byte[] decryptedSecretKey = spliter.decryptSecretKeyData(spliter.encryptedSecretKey, spliter.iv, privateKeyData);

      System.out.println("Decrypted Secret ");

      byte[] decr = spliter.decryptData(spliter.getEncryptedData(), spliter.iv, decryptedSecretKey);

      byte[] text = spliter.trimHMAC(decr);
      Files.write(Paths.get("NpciResponseDecyprted.xml"), text);
      System.out.println("Actual Text is written into NpciResponseDecyprted.xml");

    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}