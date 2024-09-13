import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.Flow;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
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

public class KycClient {
  final static String P12_PASSWORD = "public";
  final static String KEY_PASSWORD = "public";

  public static void main(String[] args) throws Exception {

    // set the timestamp in the PID XML
    Node kycNode = createKycNode();
    setRad(kycNode);

    HttpClient client = createHttpClient();

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(
            "https://developer.uidai.gov.in/uidkyc/kyc/2.5/public/9/9/MHyryrzsW4_lgSJB1jQ-zQhd022ODevHJ6SeJJIR2IMi5KwN91Wxgps"))
        .header("Content-Type", "application/xml")
        .timeout(Duration.ofSeconds(60))
        .POST(HttpRequest.BodyPublishers.ofString(nodeToString(kycNode)))
        .build();

    HttpClientLogger.logRequestBody(request);

    HttpResponse<String> response = client.send(request,
        HttpResponse.BodyHandlers.ofString());

    System.out.println("Status Code: " + response.statusCode());
    System.out.println("Response Body: " + response.body());
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

  private static void setRad(Node kycNode) throws Exception {
    // Read the Auth XML
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    DocumentBuilder builder = factory.newDocumentBuilder();

    Document doc = builder.parse(new ByteArrayInputStream(AUTH_XML.getBytes()));

    Node authNode = doc.getElementsByTagName("Auth").item(0);
    String authXml = nodeToString(authNode);

    // AuthXml is base64 encoded before setting it in the Rad Element
    String authXmlBase64 = Base64.getEncoder().encodeToString(authXml.getBytes());

    Node radNode = ((Element) kycNode).getElementsByTagName("Rad").item(0);
    radNode.setTextContent(authXmlBase64);
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
  private static String KYC_XML = """
    <Kyc ver="2.5" ra="O" rc="Y" lr="N" de="N" pfr="N">
      <Rad/>
    </Kyc>
      """;

  /** The PID XML (before encryption) */
  private static String AUTH_XML = """
    <Auth ac="public" lk="MOSuHNHE9vz9h-6m0ZNAocEIWN4osP3PObgu183xWNxnyM3JGyBHw0U" rc="Y" sa="" tid="" txn="TX001" uid="999941057058" ver="2.5">
      <Uses bio="n" bt="n" otp="y" pa="n" pfa="n" pi="y" pin="n"/>
      <Device dc="" dpId="" mc="" mi="" rdsId="" rdsVer=""/>
      <Skey ci="20250825">XUEqnBMtGzerj7CTonYYJlQ++7Gvpbr4Sa9b+12ok+WCnACC6kNBxX1kJuRFyB6Mg1Ij0UEftqCz/4Y5nU9CRVhZsSvbWaZbkdDV0TizPOdEghTSqd9xyf2xBduVVNb9SyQcm1iyXHbwN3soZ3d3h8q5VM7lh/+SlHUjsUmLe9lGD0N2PfRd17TmHNx/OgiJOF29cvXREtznSxelaTnPJXg+hsy9TB8Ik1ige0aZcpZcBPXzdr98AfPEik71nVg7vuGBveaM9DiTVEbaA6Oy3WCzhIu2DsnzSXDdaaJdQ5rj8YOlypffkJ6zzzzJefcMxQwV/QApLQSeJnOV8INTBQ==</Skey>
      <Hmac>T1qgVG5VGFFUyikesyVNLbuq1kzwmMYdtNv96HIq4yDpvd7Q1D6iZXZWw2B9KMzc</Hmac>
      <Data type="X">BcGRflYyor/8yv8/IoDm6aI61sKYhNPEO+QbSfX+1xi2ZvkFUiMEwSRGWe39txtjd7chFMOz43Gf29aGi2frnH4c/EPUKNK2ZxfdmmNJNlthtgDzv7Ir9y0czMBi8+2sTCkfmxvcJXEN71um3rEEHqEp1V5LgmlBKIC/SfxRYLoCZw16o/rtCoCVVHW0C1A+eS3h6YkaaShWvJ1h17VqwQxT8Te6zxdj/1EWbNw0LTA5LTEzVDA4OjQwOjA5MjAyNC0wOS0xM1QwODo0MDowOQ==</Data>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI=""><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>OYoqBHveTasbMofG+R0f570JWyvdTryYel3CR4UOggo=</DigestValue></Reference></SignedInfo><SignatureValue>Y6qtwmwda/XTsxi/YwY7ePekK0DtbWs9wNH3rH+TE/ItIADfTs7pRSI6oj+yH21M7dphS06reN4k&#13;
    DLer9vGPoH3TFK112G7lbmiyEI9h70tAD7oaEx0dzCEKJ41TtXDgg/jX/o3dMApCE741SbGGdoLD&#13;
    B1NsZLrfglio94X1g3Oovl3rVf5yodvHAjuqnKWY/Sp8FlW0A8s6t6X4qDVyMfCZoVjSehEZbRkC&#13;
    m0BsblqOZc5NFAdaaHV/l3L4z8XmdD9THcOh8J3s7VzNf3Wt2wCFsFhK9LvFO3sh+KHF59nR7g/W&#13;
    qsihPVjnwBrIWAJH5f/l/GoVAwkKbUiGZ0eoHg==</SignatureValue><KeyInfo><X509Data><X509SubjectName>CN=Public AUA for Staging Services,OU=Staging Services,O=Public AUA,L=Bangalore,ST=KA,C=IN</X509SubjectName><X509Certificate>MIIDuTCCAqGgAwIBAgIHBFednVbC3DANBgkqhkiG9w0BAQUFADCBjTELMAkGA1UEBhMCSU4xCzAJ&#13;
    BgNVBAgTAktBMRIwEAYDVQQHEwlCYW5nYWxvcmUxEzARBgNVBAoTClB1YmxpYyBBVUExGTAXBgNV&#13;
    BAsTEFN0YWdpbmcgU2VydmljZXMxLTArBgNVBAMTJFJvb3QgUHVibGljIEFVQSBmb3IgU3RhZ2lu&#13;
    ZyBTZXJ2aWNlczAeFw0yNDA0MjkxMzI3MDZaFw0yODA0MjkxMzI3MDZaMIGIMQswCQYDVQQGEwJJ&#13;
    TjELMAkGA1UECBMCS0ExEjAQBgNVBAcTCUJhbmdhbG9yZTETMBEGA1UEChMKUHVibGljIEFVQTEZ&#13;
    MBcGA1UECxMQU3RhZ2luZyBTZXJ2aWNlczEoMCYGA1UEAxMfUHVibGljIEFVQSBmb3IgU3RhZ2lu&#13;
    ZyBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALiYzM/HKKAWW+qZD7Ex&#13;
    GEI4XFb+dT5bZElYBickVN5rj6g0p7psJDr6Ls//6v7f1SThdEDvwx0vavN6tzW+hdlBGmN7T6Nz&#13;
    zqwkL5P6PJHwRY6on4n9edLB+Izn2a/qdlRB/gmV5cvH2eL2GqOsjhrGizj0Q+wsmNtnYwjKbtIN&#13;
    LYSO7pUmePkSmkBk5eG8HjwmFcVmqkOoaCAEwz91iHsXLrSuh4CdmM8bWLMO5WNsdceLdml/6RLf&#13;
    S4c0MwL1WgUU95LJuikeKz95p9HCq7GK0uZk2UhjtmyxoE9ccuidvcDHX9Xlb3uk1bScs4xEarwA&#13;
    llT+vRI9BezfNwyk7s8CAwEAAaMhMB8wHQYDVR0OBBYEFD2MCJqrkkUJz4tnNLXn7Cl2hSAyMA0G&#13;
    CSqGSIb3DQEBBQUAA4IBAQB7BlVIyhCf2A5IuN6PHtgBr7NOGYYFyQVwBoS9pmQaqTE1km5f2m+x&#13;
    Fh7UD635NAXuUA0USXBYhN1NMgnE3q/Jhyfxq0Zx0Qq8WFQaBM8ka93r833t+jvLUrIlHlq5K4V7&#13;
    UNyOnks+lyPGp2WwG1cI1NUgq5HInwy2sDJIFAAbTWiVXxzSnK0mA9jbATx8kcoudqbtkeYIKF3R&#13;
    F1ngvb35LPSo5SQDnXbFB22pVfSSv2Lo4viNVy924/z176uz21LU/FspnfqVKR4Cprl2eBslcNnb&#13;
    Hv2CSfadPAdw4ncASgZLDaZlfywzZ20+zGF7IDN5opx+sBPhhv64hkmupO1Y</X509Certificate></X509Data></KeyInfo></Signature></Auth>
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