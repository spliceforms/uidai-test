import java.io.ByteArrayInputStream;
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
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
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

import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.text.SimpleDateFormat;

public class AuthClientNsdl {
  final static String P12_PASSWORD = "public";
  final static String KEY_PASSWORD = "public";
  static boolean signatureFlag = false;

  public static void main(String[] args) throws Exception {
    final KeyStore keyStore;
    String alias;
    String uid = "578796332042";
    String otp = "342947";

    // read the p12 file that has the private key for AUA
    if (args.length < 3) {
      System.out.println(
          "Please provide the p12 file & alias, ensure key-password and file password is 'public, and the OTP");
      return;
    } else {
      System.out.println("Using p12 file: " + args[0] + ", and alias " + args[1]
          + " assuming key-password and file password is 'public'");
      keyStore = createKeyStore(args[0], P12_PASSWORD);
      alias = args[1];
      otp = args[2];
    }

    // optionally a UID can be passsed
    if (args.length == 4) {
      uid = args[3];
    }
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
    if (signatureFlag) {
      // add the signature to the Auth XML
      System.out.println("Adding ignature");
      addSignature(authNode, keyStore, alias);
    }

    String path = "authserver";
    String payload = nodeToString(authNode);
    // optionally kyc can be triggered

    System.out.println(
        "------------------------------------------AuthRequestNsdl-------------------------------------  ");
    HttpClient client = createHttpClient();

    String formData1 = "eXml=" + "A57" + payload;
    String formData = "eXml=" + URLEncoder.encode("A57 " + payload, StandardCharsets.UTF_8);

    System.out.println(formData1);
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(
            "https://preprodsa.egov-nsdl.com/TIN/ASA"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration.ofSeconds(60))
        .POST(HttpRequest.BodyPublishers.ofString(formData))
        .build();
    System.out.println("--------------------------AuthRequestNSdl-----------------------------------------");

    // HttpClientLogger.logRequestBody(request);

    HttpResponse<String> response = client.send(request,
        HttpResponse.BodyHandlers.ofString());

    System.out.println("Status Code: " + response.statusCode());
    System.out.println("Response Body: " + response.body());
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

  private static void setRad(Node kycNode, Node authNode) throws Exception {
    // Read the Auth XML
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();

    Document doc = builder.parse(new ByteArrayInputStream(AUTH_XML.getBytes()));

    String authXml = nodeToString(authNode);

    // AuthXml is base64 encoded before setting it in the Rad Element
    String authXmlBase64 = Base64.getEncoder().encodeToString(authXml.getBytes());

    Node radNode = ((Element) kycNode).getElementsByTagName("Rad").item(0);
    radNode.setTextContent(authXmlBase64);
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

  /*
   * Helper function to add the signature to the XML
   */
  private static void addSignature(Node authNode, KeyStore keyStore, String alias) throws Exception {
    XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

    // Create a Reference to the enveloped document
    Reference ref = fac.newReference("", fac.newDigestMethod(DigestMethod.SHA256, null),
        Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
        null, null);

    SignedInfo sInfo = fac.newSignedInfo(
        fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
        fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
        Collections.singletonList(ref));

    PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, KEY_PASSWORD.toCharArray());

    X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
    List<Object> x509Content = new ArrayList<>();
    x509Content.add(cert.getSubjectX500Principal().getName());
    x509Content.add(cert);
    X509Data xd = fac.getKeyInfoFactory().newX509Data(x509Content);
    KeyInfo kInfo = fac.getKeyInfoFactory().newKeyInfo(Collections.singletonList(xd));

    DOMSignContext dsc = new DOMSignContext(privateKey, authNode);
    XMLSignature signature = fac.newXMLSignature(sInfo, kInfo);
    signature.sign(dsc);
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
   * Helper function to create a KeyStore from a p12 file
   */
  private static KeyStore createKeyStore(String p12File, String p12Password) throws Exception {
    byte[] p12FileBytes = Files.readAllBytes(Paths.get(p12File));
    KeyStore keystore = KeyStore.getInstance("PKCS12");
    keystore.load(new ByteArrayInputStream(p12FileBytes), p12Password.toCharArray());
    return keystore;
  }

  /*
   * HTTP Client with SSLContext that trusts https://developer.uidai.gov.in
   */

  private static HttpClient createHttpClient() throws Exception {
    X509Certificate cert = readCertificate(DEVELOPER_NSDL_GOV_IN_TLS_CERTIFICATE);

    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    keyStore.load(null, null);
    keyStore.setCertificateEntry("cert", cert);

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(keyStore);

    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, tmf.getTrustManagers(), null);

    return HttpClient.newBuilder()
        .sslContext(sslContext)
        .connectTimeout(Duration.ofSeconds(10))
        .build();
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
      <Auth xmlns="http://www.uidai.gov.in/authentication/uid-auth-request/2.0" ac="STGHDFC001" lk="ML1lTKYvTDM_3Ji0S42LTPkd98kru54qQH0cVJPG6Q6VxbF9839-Z10" rc="Y" sa="STGHDFC001" tid="" txn="apibanking:00049" uid="578796332042" ver="2.5" >
      <Uses pi="n" pa="n" pfa="n" bio="n" bt="" pin="n" otp="y"/>
      <Meta rdsId="" rdsVer="" dpId="" dc="" mi="" mc=""/>
      <Skey ci=""/>
      <Data type="X"/>
      <Hmac/>
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">STGHDFC001</Signature></Auth>
      """;

  /** The PID XML (before encryption) */
  private static String PID_XML = """
      <Pid ts="" ver="2.0" wadh="">
      <Demo lang=""/>
      <Pv otp="302690" />
      </Pid>
      """;

  /*
   * The certificate for https://preprodsa.egov-nsdl.com
   * openssl s_client -showcerts -servername developer.uidai.gov.in -connect
   * developer.uidai.gov.in:443 </dev/null
   */
  private static final String DEVELOPER_NSDL_GOV_IN_TLS_CERTIFICATE = """
      -----BEGIN CERTIFICATE-----
      MIIG3DCCBcSgAwIBAgIQaFANLoGQ0pRzRPaRyZNaKjANBgkqhkiG9w0BAQsFADCB
      ujELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUVudHJ1c3QsIEluYy4xKDAmBgNVBAsT
      H1NlZSB3d3cuZW50cnVzdC5uZXQvbGVnYWwtdGVybXMxOTA3BgNVBAsTMChjKSAy
      MDEyIEVudHJ1c3QsIEluYy4gLSBmb3IgYXV0aG9yaXplZCB1c2Ugb25seTEuMCwG
      A1UEAxMlRW50cnVzdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEwxSzAeFw0y
      MzExMjAwNjM5MTdaFw0yNDExMjAwNjM5MTZaMIGEMQswCQYDVQQGEwJJTjEWMBQG
      A1UECAwNTWFoxIFyxIFzaHRyYTEPMA0GA1UEBxMGTXVtYmFpMSowKAYDVQQKEyFQ
      cm90ZWFuIGVHb3YgVGVjaG5vbG9naWVzIExpbWl0ZWQxIDAeBgNVBAMTF3ByZXBy
      b2RzYS5lZ292LW5zZGwuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
      AQEAtAIW5LCQN/Ov3PeLvoiewY+al9rZ6kYve8iz970R9bL+TX+1iMKzr/H1Iu4N
      eL/WDSnoyhNnw6Elje8m5ZAJJskFw538n3QTgpf8796cCIWPcJcM//ChbrBxd6c+
      6orzD+QpyzFgC0g6Eb1FynQ542Vber8agcAk8nc/GFEDqDZi9Ysz8JE4WrAU+P5r
      8jNiqrRHDGNLiIhx0kBKXA0y1ohwWVOgAgftLj9I4e0Xc8wkBd2XmKuMGrWdgFck
      oRMLwtAgcsrS95J56E3ZlMM2bVG+J4Dc4qxxuF1zoZ65y1gYy3LDu2k8sy2AvbPz
      hxUfjFonBqDvlQQ3rFXfkkkbDwIDAQABo4IDEDCCAwwwDAYDVR0TAQH/BAIwADAd
      BgNVHQ4EFgQUWnXKqVoSf/SmNN575pVjr/miy78wHwYDVR0jBBgwFoAUgqJwdN28
      Uz/Pe9T3zX+nYMYKTL8waAYIKwYBBQUHAQEEXDBaMCMGCCsGAQUFBzABhhdodHRw
      Oi8vb2NzcC5lbnRydXN0Lm5ldDAzBggrBgEFBQcwAoYnaHR0cDovL2FpYS5lbnRy
      dXN0Lm5ldC9sMWstY2hhaW4yNTYuY2VyMDMGA1UdHwQsMCowKKAmoCSGImh0dHA6
      Ly9jcmwuZW50cnVzdC5uZXQvbGV2ZWwxay5jcmwwWAYDVR0RBFEwT4IXcHJlcHJv
      ZHNhLmVnb3YtbnNkbC5jb22CG3d3dy5wcmVwcm9kc2EuZWdvdi1uc2RsLmNvbYIX
      cHJlcHJvZHVhLmVnb3YtbnNkbC5jb20wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW
      MBQGCCsGAQUFBwMBBggrBgEFBQcDAjATBgNVHSAEDDAKMAgGBmeBDAECAjCCAX0G
      CisGAQQB1nkCBAIEggFtBIIBaQFnAHcA7s3QZNXbGs7FXLedtM0TojKHRny87N7D
      UUhZRnEftZsAAAGL63RuTwAABAMASDBGAiEAs4yiEJYtzcXGEWbFeY9Td/Yj6s2D
      OUmmAM326/C3BrMCIQCdJ8Wg8eTU+A9PyEbwEpQ6Edwp1+yQr0+0gAYMJQenbwB1
      AD8XS0/XIkdYlB1lHIS+DRLtkDd/H4Vq68G/KIXs+GRuAAABi+t0boIAAAQDAEYw
      RAIgDCirp+Q6qGVwCiOQgGqQzKSGFpYd+Z0m3N21DnKAhBMCIFHeeTijkkTQo8Pq
      Vyj9NcrR/dw9VUZXZMBI7MgsyGU2AHUA2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0
      vaQ9MEjX+6sAAAGL63RujgAABAMARjBEAiBfLdiRLkqkE7AjDF3DMtRQ3eOzOCXK
      lpcqnPJ2eZSLfQIgIMx6gr10lsYduP4gJa9FLH+bfqah2hYYTF+pFNsoLOEwDQYJ
      KoZIhvcNAQELBQADggEBAGkU8m1/Zv/4tC1MnoxNLoAsS3uCWlTOdbfBbteh5HQW
      hFFtGkKbZKTj2NDSqkz2SmEaaZMPNYPC4yOG/xuytnHSv6KxN3qCIv+aTqhAqM/b
      Jpf5S3wy85avIw8Xqr0CRlY1TnbXprP871pNKDfbw5gztGpBae8Sjil/bKjBQOwQ
      A3AdhuDvTSRseAFw1aX+Yi38x2F9tOg445jtsGP0LafHqVJmUbA+bHthnUX//NRb
      Lrp64xfYai1Pu+R5HW4UbB+rQw6T2cEE9AaSEgBPkMN3mZBCckrrIYDtWi3LKKjh
      y/G7UXmugFYl8JGvNQfODMBfizOsRihbokUP7anx5NU=
      -----END CERTIFICATE-----
            """;

  /*
   * The certificate that has the UIDAI public key for encryption of SessionKey
   * AuthStaging25082025.cer
   * https://uidai.gov.in/en/ecosystem/authentication-devices-documents/developer-
   * section/916-developer-section/data-and-downloads-section.html.
   */

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