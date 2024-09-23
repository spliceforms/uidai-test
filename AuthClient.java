import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.URI;
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

public class AuthClient {
  final static String P12_PASSWORD = "public";
  final static String KEY_PASSWORD = "public";

  public static void main(String[] args) throws Exception {
    final KeyStore keyStore;
    String alias;
    String uid = "999941057058";
    String otp = "123456";

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

    // add the signature to the Auth XML
    addSignature(authNode, keyStore, alias);

    String path = "authserver";
    String payload = nodeToString(authNode);
    // optionally kyc can be triggered
    if (args.length == 5 && args[4].equals("kyc")) {
      System.out.println("Doing KYC instead of Auth");
      path = "uidkyc/kyc";

      Node kycNode = createKycNode();
      setRad(kycNode, authNode);
      payload = nodeToString(kycNode);
    }


    HttpClient client = createHttpClient();

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(
            "https://developer.uidai.gov.in/" + path
                + "/2.5/public/9/9/MHyryrzsW4_lgSJB1jQ-zQhd022ODevHJ6SeJJIR2IMi5KwN91Wxgps"))
        .header("Content-Type", "application/xml")
        .timeout(Duration.ofSeconds(60))
        .POST(HttpRequest.BodyPublishers.ofString(payload))
        .build();

    HttpClientLogger.logRequestBody(request);

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
    X509Certificate uidaiCertificate = readCertificate(UIDAI_STAGING_ENCRYPTION_CERTIFICATE);

    System.out.println("Skey: PSource " + pidTs);

    Cipher pkCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    var pSrc = new PSource.PSpecified(pidTs.getBytes());
    var spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, pSrc);
    pkCipher.init(Cipher.ENCRYPT_MODE, uidaiCertificate.getPublicKey(), spec);

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

  private static Node createKycNode() throws Exception {
    // Create a DocumentBuilder
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();

    // Parse the XML string
    Document doc = builder.parse(new ByteArrayInputStream(KYC_XML.getBytes()));

    Node kycNode = doc.getElementsByTagName("Kyc").item(0);

    return kycNode;
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
    X509Certificate cert = readCertificate(DEVELOPER_UIDAI_GOV_IN_TLS_CERTIFICATE);

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
      <Auth uid="" rc="Y" tid="" ac="public" sa="" ver="2.5" txn="UKC:001" lk="MOSuHNHE9vz9h-6m0ZNAocEIWN4osP3PObgu183xWNxnyM3JGyBHw0U">
        <Uses pi="n" pa="n" pfa="n" bio="n" bt="" pin="n" otp="y"/>
        <Device rdsId="" rdsVer="" dpId="" dc="" mi="" mc=""/>
        <Skey ci=""/>
        <Hmac/>
        <Data type="X"/>
      </Auth>
      """;

  /** The PID XML (before encryption) */
  private static String PID_XML = """
      <Pid ts="" ver="2.0" wadh="">
        <Demo lang="" />
        <Pv otp="123456" />
      </Pid>
      """;

  /** KCY XML */
  private static String KYC_XML = """
      <Kyc ver="2.5" ra="O" rc="Y" lr="N" de="N" pfr="N">
        <Rad/>
      </Kyc>
        """;

  /*
   * The certificate for https://developer.uidai.gov.in
   * openssl s_client -showcerts -servername developer.uidai.gov.in -connect
   * developer.uidai.gov.in:443 </dev/null
   */
  private static final String DEVELOPER_UIDAI_GOV_IN_TLS_CERTIFICATE = """
      -----BEGIN CERTIFICATE-----
      MIIGoTCCBYmgAwIBAgIPVGvzhgB+CuX3S15f/dMlMA0GCSqGSIb3DQEBCwUAMGYx
      CzAJBgNVBAYTAklOMRMwEQYDVQQLEwplbVNpZ24gUEtJMSUwIwYDVQQKExxlTXVk
      aHJhIFRlY2hub2xvZ2llcyBMaW1pdGVkMRswGQYDVQQDExJlbVNpZ24gU1NMIENB
      IC0gRzEwHhcNMjQwNzE4MTE1NjI3WhcNMjUwODEyMTE1NjI3WjCBgTELMAkGA1UE
      BhMCSU4xEjAQBgNVBAgMCUthcm5hdGFrYTESMBAGA1UEBwwJQmFuZ2Fsb3JlMTEw
      LwYDVQQKDChVTklRVUUgSURFTlRJRklDQVRJT04gQVVUSE9SSVRZIE9GIElORElB
      MRcwFQYDVQQDDA4qLnVpZGFpLmdvdi5pbjCCASIwDQYJKoZIhvcNAQEBBQADggEP
      ADCCAQoCggEBAJUfAeZ/J3oUKm+4qASUZDvnroRPQjxnX/UzV7xwNobj2HWNoUC3
      4IN4GieeHBcXn3vTVNCYqpR5Y4Y21T9jcGv/LKKFYws6jAFyNa5/vo/jcYC7TTZZ
      2cls3Xk+gnumIYF/qLMgpO7IxgUatvLkq53e23olkl+hb/WPfEjP2fS29f8QbZ7T
      lmtP+uzEb1NiGiAMkw0JnI12w6bJ8dI2XEhQqu3kX3XtGpx8Q0tKjj1KqVomv9IL
      4Naqnx0VVU4k+xNA2ku0Zx2ejnnrFnv87R2qezuFm4r4L/HYa+bH/zBD1DEqgfJ3
      tJ0PHdaWskbgAkqWOymaqgm2uHITUHZ6UFUCAwEAAaOCAy4wggMqMB8GA1UdIwQY
      MBaAFDTR9zkyRUBKmSt9iWpXaa2Vr+M3MB0GA1UdDgQWBBRxLit5vO933sz9O91W
      cI3LxPd59zAnBgNVHREEIDAeggx1aWRhaS5nb3YuaW6CDioudWlkYWkuZ292Lmlu
      MA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw
      OAYDVR0fBDEwLzAtoCugKYYnaHR0cDovL2NybC5lbXNpZ24uY29tP2VtU2lnblNT
      TENBRzEuY3JsME4GA1UdIARHMEUwOQYLKwYBBAGDjiEBAAEwKjAoBggrBgEFBQcC
      ARYcaHR0cDovL3JlcG9zaXRvcnkuZW1TaWduLmNvbTAIBgZngQwBAgIwdAYIKwYB
      BQUHAQEEaDBmMCIGCCsGAQUFBzABhhZodHRwOi8vb2NzcC5lbVNpZ24uY29tMEAG
      CCsGAQUFBzAChjRodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL2Vt
      U2lnblNTTENBRzEuY3J0MAwGA1UdEwEB/wQCMAAwggGABgorBgEEAdZ5AgQCBIIB
      cASCAWwBagB3ABLxTjS9U3JMhAYZw48/ehP457Vih4icbTAFhOvlhiY6AAABkMWz
      edQAAAQDAEgwRgIhAIcyIUd+9dfvH6IjOo0RmFSSkbVi8+C5Zj9TY2113OxhAiEA
      sdu+6x5z8yzX6soVILeeRTAm6CLRDbc2VuWf6zGWVEgAdwDM+w9qhXEJZf6Vm1PO
      6bJ8IumFXA2XjbapflTA/kwNsAAAAZDFs3xbAAAEAwBIMEYCIQCRICoYRrSSL7SM
      Lkp3i+QQyW9lfZGyI3w9t1W5t1l3mgIhAO27nC1lkCEH9BG2U6vaMviCIu1fk8EI
      zUwb/V55VH5mAHYADeHyMCvTDcFAYhIJ6lUu/Ed0fLHX6TDvDkIetH5OqjQAAAGQ
      xbOFAQAABAMARzBFAiB6k5O1mShzToXcP7fQCBhOPMEipKJrna4DgCDPYXqwwwIh
      ANUCR/5sTxDQ40g0/UC0+VmK2PbhM45/ORgdx2/r60/iMA0GCSqGSIb3DQEBCwUA
      A4IBAQAs5dHjCpx6kcNJuRUcMP0XKxkP/uf3u5Ee1LvLiKveQrARD9JF5k8RQE5K
      h8ETdHyd9rGnePN7Xlw2OZGBezwGJge2ZeJ/pTI0Ex/ZMI0Lg1PW2sXfK72WPJTK
      MuX7x8JjvmQ4QrZoiKkiwLyQq6k8RlbjyQRy/Xi/PPYhPBsOoj2o/uKzqqJY/PD0
      LRXcIQI9VdjRzNJ+1XBAPf+UDB4XNkErj6B/CPfA448qiG/nBuEEf0fhVzm7cN+7
      x2fiTrbGIQOa0dbsRDV8mgSuQCE+RNoiOCPkJPaGro39HVdVvityw9ZAuVlMtDrJ
      htyV+2PXRYG98gP4PCp5RF5H1uxs
      -----END CERTIFICATE-----
      """;

  /*
   * The certificate that has the UIDAI public key for encryption of SessionKey
   * AuthStaging25082025.cer
   * https://uidai.gov.in/en/ecosystem/authentication-devices-documents/developer-
   * section/916-developer-section/data-and-downloads-section.html.
   */

  private static final String UIDAI_STAGING_ENCRYPTION_CERTIFICATE = """
      -----BEGIN CERTIFICATE-----
      MIID5DCCAsygAwIBAgIEATMzfzANBgkqhkiG9w0BAQsFADCBqTELMAkGA1UEBhMC
      SU4xEjAQBgNVBAgTCUthcm5hdGFrYTESMBAGA1UEBxMJQmFuZ2Fsb3JlMQ4wDAYD
      VQQKEwVVSURBSTEcMBoGA1UECxMTQXV0aFN0YWdpbmcyNTA4MjAyNTEcMBoGA1UE
      AxMTQXV0aFN0YWdpbmcyNTA4MjAyNTEmMCQGCSqGSIb3DQEJARYXYW51cC5rdW1h
      ckB1aWRhaS5uZXQuaW4wHhcNMjAwODI1MDAwMDAwWhcNMjUwODI1MDAwMDAwWjCB
      qTELMAkGA1UEBhMCSU4xEjAQBgNVBAgTCUthcm5hdGFrYTESMBAGA1UEBxMJQmFu
      Z2Fsb3JlMQ4wDAYDVQQKEwVVSURBSTEcMBoGA1UECxMTQXV0aFN0YWdpbmcyNTA4
      MjAyNTEcMBoGA1UEAxMTQXV0aFN0YWdpbmcyNTA4MjAyNTEmMCQGCSqGSIb3DQEJ
      ARYXYW51cC5rdW1hckB1aWRhaS5uZXQuaW4wggEiMA0GCSqGSIb3DQEBAQUAA4IB
      DwAwggEKAoIBAQCtnXWu8+uja+Us3z+TWjY1yV5KZq8I4CT9oHVk0hOMOhZz5Vas
      h4mvj4mHa8u9y2/qZXIdIB8s006k2jz0dvnpBiMFzoJoQ5TSPwJl13gGKu/NTPro
      BIELiDnOESfOFevQas48hMbHxvRIIrTUIZ+wL017uXCF/UIamdwRZ8SSoN897tWw
      rRmSutpsgDCE/F4k88XzfOyx2UyG+kJJZOYIWeYWMhLRH4ascP/OE1/9BtJ31wZE
      ZFEUp0Saat5KNWLlDhKF4R8mwJc7+OMIOw5YPyjY/iW/OyoEwgxvjgqCizlWZnv+
      oRq8yBxtBkfwkakwxYv1rOamNbHpET30EB2TAgMBAAGjEjAQMA4GA1UdDwEB/wQE
      AwIF4DANBgkqhkiG9w0BAQsFAAOCAQEAVGhmm2h3d8aOBhoZonAN6C5W1NY0hsuK
      P7xZ3ZyVeEhs1/DIavaPmrNx3LISEJZ9UDwGJdP/6+1M86DXUK5dvyjpfQOESxnX
      FNqvbuQkh2C/IxawCWjQCjWgUm+yyRXnpvcgLGNYGhKxnmuZVJwJOlScc/6wjqvO
      NscPV+neHwerrbFBq8DwXGgqiJU2dijRFpChhN09PSbkQ/y2ACOBOS87XJrcxBP+
      AyBSTdQNG+q94Ww/PKBDgIvnR2JzpYA+eHqu45CJDy5zA1oHT1N7JZlm5GPe798g
      5GMrBfd/CZ5GTeGRS+MNSAGmD3BjankxWFWMVdNiXjLs400EZdKQGg==
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