
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
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Flow;

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

public class OtpClientNpci {

  // Path to your .pfx file and its password
  final static String pfxFile = "spliceforms_com.pfx";
  final static String pfxPassword = "changeit";

  public static void main(String[] args) throws Exception {
    KeyStore keyStore = null;
    String alias = null;

    LocalDateTime now = LocalDateTime.now();
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
    final String NOW = now.format(formatter);
    final Node otpNode = createOtpNode(NOW);

    System.out.println(
        "------------------------------------------OtpRequestNpci-------------------------------------  ");
    System.out.println(nodeToString(otpNode));
    // HttpClient client = createHttpClient();

    HttpClient client = createHttpClient();

    // HttpClient client = HttpClient.newBuilder()
    // .connectTimeout(Duration.ofSeconds(60))
    // .followRedirects(HttpClient.Redirect.NORMAL)
    // .build();

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(
            "https://api-uat.hdfcbank.com/api/npci-passthrough/AEPS/XML/otpSupport"))
        .header("Content-Type", "application/xml")
        .header("apikey", "1zYlb4w9j6KpuGOr8SvVxsVi9G5XGGZCkmT2jyFfy2FFOCH1")
        .timeout(Duration.ofSeconds(60))
        .POST(HttpRequest.BodyPublishers.ofString(nodeToString(otpNode)))
        .build();
    System.out.println("--------------------------OtpRequestNpci-----------------------------------------");
    // HttpClientLogger.logRequestBody(request);

    HttpResponse<String> response = client.send(request,
        HttpResponse.BodyHandlers.ofString());

    System.out.println("Status Code: " + response.statusCode());
    System.out.println("Response Body: " + response.body());
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
    Node otpRequest = doc.getElementsByTagName("OtpRequest").item(0);
    Node otp = doc.getElementsByTagName("Otp").item(0);
    otp.getAttributes().getNamedItem("ts").setTextContent(ts);
    return otpRequest;
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
        <OtpRequest>
          <TransactionInfo>
              <Pan>6071520230999761316</Pan>
              <Proc_Code>140000</Proc_Code>
              <Transm_Date_time>0723105913</Transm_Date_time>
              <Stan>786624</Stan>
              <Local_Trans_Time>105913</Local_Trans_Time>
              <Local_date>0723</Local_date>
              <Mcc>6012</Mcc>
              <Pos_entry_mode>019</Pos_entry_mode>
              <Pos_code>05</Pos_code>
              <AcqId>200030</AcqId>
              <RRN>420510786624</RRN>
              <CA_Tid>register</CA_Tid>
              <CA_ID>HDF000000000001</CA_ID>
              <CA_TA>HDFC BANK LTD KanjurmarMumbai MHIN</CA_TA>
          </TransactionInfo>
          <Otp uid="230999761316" ts="" ac="STGHDFC001" sa="STGHDFC001" ver="2.5" txn="apibanking:000265" type="A" lk="ML1lTKYvTDM_3Ji0S42LTPkd98kru54qQH0cVJPG6Q6VxbF9839-Z10">
              <Opts ch="01"/>
          </Otp>
      </OtpRequest>
        """;
}