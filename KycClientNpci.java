import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.TimeZone;
import java.util.concurrent.Flow;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.text.SimpleDateFormat;

public class KycClientNpci {
  // Path to your .pfx file and its password
  final static String pfxFile = "spliceforms_com.pfx";
  final static String pfxPassword = "changeit";

  static boolean signatureFlag = false;

  public static void main(String[] args) throws Exception {
    final KeyStore keyStore;
    String alias;
    String uid = "578796332042";
    String otp = "128580";

    System.out.println("Using UID: " + uid);
    System.out.println("Using OTP: " + otp);

    // every request is with a new timestamp
    LocalDateTime now = LocalDateTime.now();
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
    final String NOW = now.format(formatter);

    // every request has a new session key
    KeyGenerator kgen = KeyGenerator.getInstance("AES");
    kgen.init(256);
    final byte[] sessionKey = kgen.generateKey().getEncoded();

    // set the timestamp in the PID XML
    Node pidNode = createPidNode(NOW, otp);
    System.out.println("PID XML: \n" + nodeToString(pidNode));

    // set the SKey, Hmac and Data in the Auth XML
    Node authNode = createAuthNode(uid);
    setSKey(authNode, NOW, sessionKey);
    setHmac(authNode, pidNode, sessionKey);
    setData(authNode, pidNode, sessionKey);

    Node kycNode = createKycNode(authNode);
    // setRad(kycNode, authNode);

    String payload = nodeToString(kycNode);

    System.out.println(
        "------------------------------------------KycRequestNpci-------------------------------------  ");
    System.out.println(payload);
    HttpClient client = createHttpClient();

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(
            "https://api-uat.hdfcbank.com/api/npci-passthrough/AEPS/XML/ekycSupport"))
        .header("Content-Type", "application/xml")
        .header("apikey", "1zYlb4w9j6KpuGOr8SvVxsVi9G5XGGZCkmT2jyFfy2FFOCH1")
        .timeout(Duration.ofSeconds(60))
        .POST(HttpRequest.BodyPublishers.ofString(payload))
        .build();
    System.out.println("--------------------------KycResponseNpci-----------------------------------------");

    // HttpClientLogger.logRequestBody(request);

    HttpResponse<String> response = client.send(request,
        HttpResponse.BodyHandlers.ofString());

    System.out.println("Status Code: " + response.statusCode());

    Files.write(Paths.get("NpciResponse.xml"), response.body().getBytes());
    System.out.println("Response saved successfully at NpciResponse.xml");
  }

  /*
   * Sets the SKey Element in the Auth XML
   * This is as per email from UIDAI dated 25th August 2024
   */
  private static void setSKey(Node authNode, String pidTs, byte[] sessionKey) throws Exception {
    X509Certificate uidaiCertificate = readCertificate(UIDAI_PREPROD_ENCRYPTION_CERTIFICATE);

    System.out.println("Skey: PSource " + pidTs);

    Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    // var pSrc = new PSource.PSpecified(pidTs.getBytes());
    // var spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
    // pSrc);
    // pkCipher.init(Cipher.ENCRYPT_MODE, uidaiCertificate.getPublicKey(), spec);
    pkCipher.init(Cipher.ENCRYPT_MODE, uidaiCertificate.getPublicKey());

    byte[] encryptedSessionKey = pkCipher.doFinal(sessionKey);

    // the encrypted session key is set in the SKey element
    Node SKeyNode = ((Element) authNode).getElementsByTagName("Skey").item(0);
    SKeyNode.setTextContent(new String(Base64.getEncoder().encode(encryptedSessionKey)));

    // the certificate identifier is set in the ci attribute of the SKey element
    // error 501 if the ci is not set
    SimpleDateFormat df = new SimpleDateFormat("yyyyMMdd");
    df.setTimeZone(TimeZone.getTimeZone("GMT"));
    String ci = df.format(uidaiCertificate.getNotAfter());

    SKeyNode.getAttributes().getNamedItem("ci").setTextContent(ci);
  }

  /*
   * Sets the Hmac Element in the Auth XML
   */
  private static void setHmac(Node authNode, Node pidNode, byte[] sessionKey) throws Exception {
    String pidTs = pidNode.getAttributes().getNamedItem("ts").getTextContent();
    byte[] pidBytes = nodeToString(pidNode).getBytes();

    // generate the SHA-256 hash of the PID block
    MessageDigest digest;
    digest = MessageDigest.getInstance("SHA-256");
    digest.reset();
    byte[] hash = digest.digest(pidBytes);

    // encrypt the hash with the sessionKey
    byte[] ciphertext = encrypt(hash, pidTs, sessionKey);

    Node hmacNode = ((Element) authNode).getElementsByTagName("Hmac").item(0);
    hmacNode.setTextContent(new String(Base64.getEncoder().encode(ciphertext)));
  }

  /*
   * Sets the Data Element in the Auth XML
   */
  private static void setData(Node authNode, Node pidNode, byte[] sessionKey) throws Exception {
    String pidTs = pidNode.getAttributes().getNamedItem("ts").getTextContent();
    byte[] pidBytes = nodeToString(pidNode).getBytes();

    // encrypt the pid XML with the sessionKey
    byte[] ciphertext = encrypt(pidBytes, pidTs, sessionKey);

    // Combine: ciphertext + AAD + full timestamp
    ByteBuffer finalData = ByteBuffer.allocate(ciphertext.length + pidTs.getBytes().length);
    finalData.put(pidTs.getBytes());
    finalData.put(ciphertext);

    Node dataNode = ((Element) authNode).getElementsByTagName("Data").item(0);
    dataNode.setTextContent(new String(Base64.getEncoder().encode(finalData.array())));
  }

  private static Node createKycNode(Node authNode) throws Exception {
    // local date and time

    String localdateTime = LocalDateTime.now().format(DateTimeFormatter.ofPattern("MMddHHmmss"));

    System.out.println("localdateTime " + localdateTime);

    // Create a DocumentBuilder
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();

    // Parse the XML string
    Document doc = builder.parse(new ByteArrayInputStream(KYC_XML.getBytes()));
    Node kycRequestNode = doc.getElementsByTagName("KycRequest").item(0);
    Node transactionInfoDateTimeNode = doc.getElementsByTagName("Transm_Date_time").item(0);
    transactionInfoDateTimeNode.setTextContent(localdateTime);

    Node LocalTransTimeNode = doc.getElementsByTagName("Local_Trans_Time").item(0);
    LocalTransTimeNode.setTextContent(localdateTime.substring(4));

    Node LocalDateNode = doc.getElementsByTagName("Local_date").item(0);
    LocalDateNode.setTextContent(localdateTime.substring(0, 4));
    System.out.println(nodeToString(authNode));
    Node kycRequestInfoNode = doc.getElementsByTagName("KycReqInfo").item(0);

    Node newAuthNode = doc.importNode(authNode, true);
    kycRequestInfoNode.appendChild(newAuthNode);

    return kycRequestNode;
  }

  private static byte[] encrypt(byte[] data, String pidTs, byte[] sessionKey) throws Exception {
    // Use last 12 bytes of ts as IV/nonce
    byte[] iv = pidTs.substring(pidTs.length() - 12).getBytes();

    // Use last 16 bytes of ts as AAD
    byte[] aad = pidTs.substring(pidTs.length() - 16).getBytes();

    // Initialize GCM cipher
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    SecretKeySpec keySpec = new SecretKeySpec(sessionKey, "AES");
    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, iv);
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
    cipher.updateAAD(aad);

    return cipher.doFinal(data);
  }

  private static Node createAuthNode(String uid) throws Exception {
    // Create a DocumentBuilder
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();

    // Parse the XML string
    Document doc = builder.parse(new ByteArrayInputStream(AUTH_XML.getBytes()));

    Node authNode = doc.getElementsByTagName("Auth").item(0);
    authNode.getAttributes().getNamedItem("uid").setTextContent(uid);

    return authNode;
  }

  /*
   * Creates a new PID - with the timestamp of now(), all other data is kept as in
   * the template
   */
  private static Node createPidNode(String ts, String otp) throws Exception {
    // Create a DocumentBuilder
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();

    // Parse the XML string
    Document doc = builder.parse(new ByteArrayInputStream(PID_XML.getBytes()));

    Node pidNode = doc.getElementsByTagName("Pid").item(0);
    pidNode.getAttributes().getNamedItem("ts").setTextContent(ts);

    Node pvNode = doc.getElementsByTagName("Pv").item(0);
    pvNode.getAttributes().getNamedItem("otp").setTextContent(otp);

    return pidNode;
  }

  /** Helper to get a String representation of the XML Document */
  private static String nodeToString(Node node) throws TransformerException {
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer transformer = tf.newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
    transformer.setOutputProperty(OutputKeys.INDENT, "no");

    StringWriter writer = new StringWriter();
    transformer.transform(new DOMSource(node), new StreamResult(writer));
    return writer.getBuffer().toString();
  }

  /*
   * HTTP Client with SSLContext that trusts https://developer.uidai.gov.in
   */

  private static HttpClient createHttpClient()
      throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException,
      UnrecoverableKeyException, KeyManagementException {

    // Load the .pfx file into a KeyStore
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (FileInputStream keyStoreInput = new FileInputStream(pfxFile)) {
      keyStore.load(keyStoreInput, pfxPassword.toCharArray());
    }

    // Create a KeyManagerFactory and TrustManagerFactory
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, pfxPassword.toCharArray());

    // Create an SSLContext with the KeyManager
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

    // Create an HttpClient with the SSLContext
    HttpClient httpClient = HttpClient.newBuilder()
        .sslContext(sslContext)
        .build();
    return httpClient;
  }

  /*
   * Helper function to read a certificate from a PEM string
   */
  private static X509Certificate readCertificate(String pem) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream certStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
    return (X509Certificate) cf.generateCertificate(certStream);
  }

  /** The Auth XML with OTP */
  private static String AUTH_XML = """
      <Auth ac="STGHDFC001" lk="ML1lTKYvTDM_3Ji0S42LTPkd98kru54qQH0cVJPG6Q6VxbF9839-Z10" rc="Y" sa="STGHDFC001" tid="" txn="UKC:apibanking:000264" uid="578796332042" ver="2.5" >
      <Uses pi="n" pa="n" pfa="n" bio="n" bt="" pin="n" otp="y"/>
      <Meta udc="HDFHL169028" rdsId="" rdsVer="" dpId="" dc="" mi="" mc=""/>
      <Skey ci=""/>
      <Data type="X"/>
      <Hmac/></Auth>
      """;

  /** The PID XML (before encryption) */
  private static String PID_XML = """
      <Pid ts="" ver="2.0" wadh="">
      <Demo lang=""/>
      <Pv otp="302690" />
      </Pid>
      """;

  /** KCY XML */
  private static String KYC_XML = """
          <KycRequest>
              <TransactionInfo>
              <Pan>6071520578796332042</Pan>
              <Proc_Code>130000</Proc_Code>
              <Transm_Date_time>0723110314</Transm_Date_time>
              <Stan>169028</Stan>
              <Local_Trans_Time>110314</Local_Trans_Time>
              <Local_date>1106</Local_date>
              <Mcc>6012</Mcc>
              <Pos_entry_mode>019</Pos_entry_mode>
              <Pos_code>05</Pos_code>
              <AcqId>200030</AcqId>
              <RRN>420511169028</RRN>
              <CA_Tid>register</CA_Tid>
              <CA_ID>HDF000000000001</CA_ID>
              <CA_TA>HDFC BANK LTD KanjurmarMumbai MHIN</CA_TA>
          </TransactionInfo>
          <KycReqInfo ver="2.5" pfr="Y" lr="Y" de="N" ra="O" rc="Y" mec=""/>
      </KycRequest>
              """;

  private static final String UIDAI_PREPROD_ENCRYPTION_CERTIFICATE = """
      -----BEGIN CERTIFICATE-----
      MIIGLjCCBRagAwIBAgIEAV9PejANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJJ

      TjEYMBYGA1UEChMPZU11ZGhyYSBMaW1pdGVkMR0wGwYDVQQLExRDZXJ0aWZ5aW5
      n
      IEF1dGhvcml0eTE2MDQGA1UEAxMtZS1NdWRocmEgU3ViIENBIGZvciBDbGFzcy
      Az
      IE9yZ2FuaXNhdGlvbiAyMDIyMB4XDTIyMDkzMDA2MjQ1NloXDTI1MDkyOTA2M
      jQ1
      NlowggEGMQswCQYDVQQGEwJJTjEOMAwGA1UEChMFVUlEQUkxDjAMBgNVBAsT
      BVVJ
      REFJMUkwRwYDVQQUE0A2Y2EyZTY4ZWE1NThlN2IzZjQ3YTFkYmI3MDAzMDc
      2MTcy
      OWFkZDM5ZTRkM2QzNmNkMzJiOGRlOWNmNWNlMzQ3MQ8wDQYDVQQREwY1Nj
      AwOTIx
      EjAQBgNVBAgTCUtBUk5BVEFLQTFJMEcGA1UEBRNAYjk5YzAwMWVmNWI2N
      zlmYTk2
      NzBmNmU4NWY2MGIwODM2NzA0YmIyNDdjZGQ5MzNjOWRhZmQ3MzkxZmNj
      NWI3ZTEc
      MBoGA1UEAxMTS2lyYW4gS3VtYXIgR3VtbWFkaTCCASIwDQYJKoZIhvc
      NAQEBBQAD
      ggEPADCCAQoCggEBANISHbd5GCG06iKXnehsryFReEnIyGCwGaGdAK
      mM4ci0cZ2d
      4JDSiFKP1n4JFicQek42hoYUZAqukCpawsZvR8prbELXtmJzt+B75
      cVTIorTg3b1
      9c/Kf6OvwgkKACmFqL8IAsjVdDZ4ldCcGzMgA8HKDp7D5nSlGpvO
      JJoCH+XeVYdR
      44phBmlRsVeGd9vJRGVRSQEewzGWVY0PeHithNjIqHBz66+9ao+
      2GvnjD1nBQOpC
      0N2S6mOFGLzu4DR4yT0J0dXhQbv6gaRMeaFaJCeifd0JE1M5B5
      JCZgIcWG+RGyhf
      mA48VyGgEIAqx5OGKx2cgweXOdpuWyjA1BAkUFsCAwEAAaOCA
      igwggIkMCEGA1Ud
      EQQaMBiBFmFkYXV0aC50Y0B1aWRhaS5uZXQuaW4wHwYDVR0j
      BBgwFoAUsg3QU6M3
      o65VgkuZPUYoHIlWS6wwHQYDVR0OBBYEFImhRhDyUvR8C55
      Hkt5VpEZ7RpnyMAwG
      A1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgUgMBkGA1UdJQ
      EB/wQPMA0GCysGAQQB
      gjcKAwQBMIG7BgNVHSAEgbMwgbAwLQYGYIJkZAIDMCMwI
      QYIKwYBBQUHAgIwFRoT
      Q2xhc3MgMyBDZXJ0aWZpY2F0ZTAtBgZggmRkAgIwIzAh
      BggrBgEFBQcCAjAVGhND
      bGFzcyAyIENlcnRpZmljYXRlMFAGB2CCZGQBCAIwRTB
      DBggrBgEFBQcCARY3aHR0
      cDovL3d3dy5lLW11ZGhyYS5jb20vcmVwb3NpdG9yeS
      9jcHMvZS1NdWRocmFfQ1BT
      LnBkZjB9BggrBgEFBQcBAQRxMG8wJAYIKwYBBQUHM
      AGGGGh0dHA6Ly9vY3NwLmUt
      bXVkaHJhLmNvbTBHBggrBgEFBQcwAoY7aHR0cDov
      L3d3dy5lLW11ZGhyYS5jb20v
      cmVwb3NpdG9yeS9jYWNlcnRzL2VtY2wzb3JnMjA
      yMi5jcnQwSQYDVR0fBEIwQDA+
      oDygOoY4aHR0cDovL3d3dy5lLW11ZGhyYS5jb2
      0vcmVwb3NpdG9yeS9jcmxzL2Vt
      Y2wzb3JnMjAyMi5jcmwwDQYJKoZIhvcNAQELB
      QADggEBAAJfBBLIWOlSRoVOoXS6
      mT80Y/9+O2OUJ5/nnjf4RMXOUEaUr3n1yIPk
      FPVcQAfFPieNPmYcmJe8ZW2ZS9LO
      gXhFzeRp+Lt4mdZ682tjAftgOseytLoLxWL
      xwY1IKz+dpqvxsiYz92WbuEpYxHI2
      kmNj1wIFrz4lI1H9Rm0LCshEziTBfWAWUl
      WIiyBgRqiWKEr59J0NkBftF3YQbbP3
      XI0jxEd+aPuKReLRp4Xh3r7TfjrU6QUzt
      GeUWX6QT+8WjG8Q2Ndyw2D1ShuSX/IP
      q/Rm8Mtt/lBBJTeNfbK0oqwcbH1Q9/Uy
      IBPilG9dzA5V4hWUYtA6DFiCsWTgwoDA
      ibY=
      -----END CERTIFICATE-----
            """;

  private static class HttpClientLogger {

    public static void logRequestBody(HttpRequest request) {
      if (request.bodyPublisher().isPresent()) {
        StringBuilder bodyBuilder = new StringBuilder();
        request.bodyPublisher().get().subscribe(new Flow.Subscriber<>() {

          @Override
          public void onSubscribe(Flow.Subscription subscription) {
            subscription.request(Long.MAX_VALUE);
          }

          @Override
          public void onNext(ByteBuffer item) {
            byte[] bytes = new byte[item.remaining()];
            item.get(bytes);
            bodyBuilder.append(new String(bytes, StandardCharsets.UTF_8));
          }

          @Override
          public void onError(Throwable throwable) {
            System.out.println("Error reading request body: " + throwable.getMessage());
          }

          @Override
          public void onComplete() {
            System.out.println("Request Body: \n" + bodyBuilder.toString());
          }
        });
      } else {
        System.out.println("No request body present");
      }
    }
  }
}