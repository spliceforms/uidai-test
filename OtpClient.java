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
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Flow;

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
import org.w3c.dom.Node;

public class OtpClient {
  final static String P12_PASSWORD = "public";
  final static String KEY_PASSWORD = "public";

  public static void main(String[] args) throws Exception {
    final KeyStore keyStore;
    String alias;
    String uid = "999941057058";

    // read the p12 file that has the private key for AUA
    if (args.length < 2) {
      System.out.println("Please provide the p12 file & alias, ensure key-password and file password is 'public");
      return;
    } else {
      System.out.println("Using p12 file: " + args[0] + ", and alias " + args[1]
          + " assuming key-password and file password is 'public'");
      keyStore = createKeyStore(args[0], P12_PASSWORD);
      alias = args[1];
    }

    // optionally a UID can be passsed
    if (args.length == 3) {
      uid = args[2];
    } 
    System.out.println("Using UID: " + uid);

    LocalDateTime now = LocalDateTime.now();
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
    final String NOW = now.format(formatter);

    final Node otpNode = createOtpNode(NOW, uid);
    addSignature(otpNode, keyStore, alias);

    HttpClient client = createHttpClient();

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(
            "https://developer.uidai.gov.in/uidotp/2.5/public/9/9/MHyryrzsW4_lgSJB1jQ-zQhd022ODevHJ6SeJJIR2IMi5KwN91Wxgps"))
        .header("Content-Type", "application/xml")
        .timeout(Duration.ofSeconds(60))
        .POST(HttpRequest.BodyPublishers.ofString(nodeToString(otpNode)))
        .build();

    HttpClientLogger.logRequestBody(request);

    HttpResponse<String> response = client.send(request,
        HttpResponse.BodyHandlers.ofString());

    System.out.println("Status Code: " + response.statusCode());
    System.out.println("Response Body: " + response.body());
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

  /*
   * Helper function to create a KeyStore from a p12 file
   */
  private static KeyStore createKeyStore(String p12File, String p12Password) throws Exception {
    byte[] p12FileBytes = Files.readAllBytes(Paths.get(p12File));
    KeyStore keystore = KeyStore.getInstance("PKCS12");
    keystore.load(new ByteArrayInputStream(p12FileBytes), p12Password.toCharArray());
    return keystore;
  }

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

  private static Node createOtpNode(String ts, String uid) throws Exception {
    // Create a DocumentBuilder
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();

    // Parse the XML string
    Document doc = builder.parse(new ByteArrayInputStream(OTP_XML.getBytes()));

    Node otpNode = doc.getElementsByTagName("Otp").item(0);
    otpNode.getAttributes().getNamedItem("ts").setTextContent(ts);
    otpNode.getAttributes().getNamedItem("uid").setTextContent(uid);

    return otpNode;
  }

  /** Helper to get a String representation of the XML Document */
  private static String nodeToString(Node node) throws TransformerException {
    TransformerFactory tf = TransformerFactory.newInstance();
    Transformer transformer = tf.newTransformer();
    transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
    transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
    transformer.setOutputProperty(OutputKeys.INDENT, "UTF-8");

    StringWriter writer = new StringWriter();
    transformer.transform(new DOMSource(node), new StreamResult(writer));
    return writer.getBuffer().toString();
  }

  /** The OTP XML */
  private static String OTP_XML = """
      <Otp ac="public" lk="MOSuHNHE9vz9h-6m0ZNAocEIWN4osP3PObgu183xWNxnyM3JGyBHw0U" sa="public" ts="" txn="TX001" type="A" uid="999945411266" ver="2.5">
        <Opts ch="00"/>
      </Otp>
      """;

  /*
   * Helper function to read a certificate from a PEM string
   */
  private static X509Certificate readCertificate(String pem) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream certStream = new ByteArrayInputStream(pem.getBytes("UTF-8"));
    return (X509Certificate) cf.generateCertificate(certStream);
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
}
