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
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class OtpClientNsdl {
  final static String P12_PASSWORD = "public";
  final static String KEY_PASSWORD = "public";

  static boolean signatureFlag = false;

  public static void main(String[] args) throws Exception {
    KeyStore keyStore = null;
    String alias = null;

    // read the p12 file that has the private key for AUA
    if (signatureFlag == true) {
      if (args.length < 2) {
        System.out.println("Please provide the p12 file & alias, ensure key-password and file password is 'public");
        return;
      } else {
        System.out.println("Using p12 file: " + args[0] + ", and alias " + args[1]
            + " assuming key-password and file password is 'public'");
        keyStore = createKeyStore(args[0], P12_PASSWORD);

        alias = args[1];
      }
    }
    LocalDateTime now = LocalDateTime.now();
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
    final String NOW = now.format(formatter);
    final Node otpNode = createOtpNode(NOW);
    if (signatureFlag) {

      addSignature(otpNode, keyStore, alias);
    }

    System.out.println(
        "------------------------------------------OtpRequestNsdl-------------------------------------  ");
    HttpClient client = createHttpClient();
    String formData1 = "eXml=" + "O57" + nodeToString(otpNode);
    String formData = "eXml=" + URLEncoder.encode("O57" + nodeToString(otpNode), StandardCharsets.UTF_8);

    System.out.println(formData1);
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(
            "https://preprodsa.egov-nsdl.com/TIN/ASA"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .timeout(Duration.ofSeconds(60))
        .POST(HttpRequest.BodyPublishers.ofString(formData))
        .build();
    System.out.println("--------------------------OtpRequestNSdl-----------------------------------------");
    // HttpClientLogger.logRequestBody(request);

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

  private static Node createOtpNode(String ts) throws Exception {
    // Create a DocumentBuilder
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();

    // Parse the XML string
    Document doc = builder.parse(new ByteArrayInputStream(OTP_XML.getBytes()));
    Node otpNode = doc.getElementsByTagName("Otp").item(0);
    otpNode.getAttributes().getNamedItem("ts").setTextContent(ts);
    if (signatureFlag != true) {

      Element newChild = doc.createElement("Signature");

      newChild.setTextContent("STGHDFC001");
      newChild.setAttribute("xmlns", "http://www.w3.org/2000/09/xmldsig#");
      otpNode.appendChild(newChild);

    }

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
      <Otp uid="578796332042" ac="STGHDFC001" sa="STGHDFC001" ver="2.5" txn="apibanking:00049" lk="ML1lTKYvTDM_3Ji0S42LTPkd98kru54qQH0cVJPG6Q6VxbF9839-Z10" ts="2024-09-30T14:25:01" type="A" xmlns="http://www.uidai.gov.in/authentication/otp/1.0"><Opts ch="00"/></Otp>
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
}