package org.apibanking;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.concurrent.Flow;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apibanking.HdfcAdvRequest.AadhaarServicessDTO;
import org.apibanking.HdfcAdvRequest.AuxData;
import org.apibanking.HdfcAdvRequest.RequestStoreString;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import com.fasterxml.jackson.databind.ObjectMapper;

public class AdvStoreData {

  // Path to your .pfx file and its password
  final static String pfxFile = "spliceforms_com.pfx";
  final static String pfxPassword = "changeit";

  public static void main(String[] args) throws Exception {
    KeyStore keyStore = null;
    String alias = null;

    LocalDateTime now = LocalDateTime.now();
    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss");
    final String NOW = now.format(formatter);
    final String kycResp = getKycResp();
    Files.write(Paths.get("kycResp.txt"), kycResp.getBytes());
    final String uid = getUidNo();

    String payload = createAdvStoreRequest(uid, kycResp);

    System.out.println(
        "------------------------------------------StoreAdvRequest-------------------------------------  ");

    // HttpClient client = createHttpClient();

    HttpClient client = createHttpClient();

    // HttpClient client = HttpClient.newBuilder()
    // .connectTimeout(Duration.ofSeconds(60))
    // .followRedirects(HttpClient.Redirect.NORMAL)
    // .build();

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(
            "https://api-uat.hdfcbank.com/OBPAPI/com.ofss.fc.cz.hdfc.obp.aadhaarvault.webservice/StoreDataSetRestWrapperService/storeDataSet"))
        .header("Content-Type", "application/json")
        .header("apikey", "1zYlb4w9j6KpuGOr8SvVxsVi9G5XGGZCkmT2jyFfy2FFOCH1")
        .timeout(Duration.ofSeconds(60))
        .POST(HttpRequest.BodyPublishers.ofString(payload))
        .build();
    System.out.println("--------------------------StoreAdvResponse-----------------------------------------");
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

  private static String getKycResp() throws ParserConfigurationException, SAXException, IOException {

    // Create a DocumentBuilderFactory and DocumentBuilder
    // DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
    // DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

    // // Parse the XML file and get the Document object
    // Document doc = dBuilder.parse(npciRespXml);
    // doc.getDocumentElement().normalize();

    // Node kycRes = doc.getElementsByTagName("KycRes").item(0);

    // return kycRes.getNodeValue();

    return Files.readString(Path.of("", "NpciResponseDecyprted.xml"), StandardCharsets.UTF_8);

  }

  private static String getUidNo() throws ParserConfigurationException, SAXException, IOException {
    File npciRespXml = new File("NsdlResponse.xml");
    // Create a DocumentBuilderFactory and DocumentBuilder
    DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
    DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

    // Parse the XML file and get the Document object
    Document doc = dBuilder.parse(npciRespXml);
    doc.getDocumentElement().normalize();

    Node kycRes = doc.getElementsByTagName("UidData").item(0);
    String uid = kycRes.getAttributes().getNamedItem("uid").getTextContent();
    System.out.println("Uid no fetched from decrypted response " + uid);
    return uid;
  }

  private static String createAdvStoreRequest(String uid, String kycResp) throws IOException {

    SessionContext sessionContext = new SessionContext();
    sessionContext.setChannel("APIGW");
    sessionContext.setUserId("DevUser01");
    sessionContext.setExternalReferenceNo("21903623");
    sessionContext.setBankCode("08");
    sessionContext.setTransactionBranch("089999");

    AuxData auxData = new AuxData("908767875433", kycResp, "ascii");

    RequestStoreString requestStoreString = new RequestStoreString("storeDataSet", "", "CRMXT", uid, "data",
        Arrays.asList(auxData));
    HdfcAdvRequest hdfcAdvRequest = new HdfcAdvRequest();
    AadhaarServicessDTO aadhaarServicesDTO = hdfcAdvRequest.new AadhaarServicessDTO(requestStoreString);

    hdfcAdvRequest.setAadhaarServicesDTO(aadhaarServicesDTO);
    hdfcAdvRequest.setSessionContext(sessionContext);

    ObjectMapper objectMapper = new ObjectMapper();
    String advPayload = objectMapper.writeValueAsString(hdfcAdvRequest);

    return advPayload;
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
}