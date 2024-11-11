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

import org.apibanking.HdfcAdvRequest.AadhaarServicesDTO;
import org.apibanking.HdfcAdvRequest.AadhaarServicessDTO;
import org.apibanking.HdfcAdvRequest.AuxData;
import org.apibanking.HdfcAdvRequest.RequestRetrievalString;
import org.apibanking.HdfcAdvRequest.RequestStoreString;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AdvGetData {

  // Path to your .pfx file and its password
  final static String pfxFile = "spliceforms_com.pfx";
  final static String pfxPassword = "changeit";

  public static void main(String[] args) throws Exception {

    String referenceKey = null;

    if (args.length < 1) {
      System.out.println("Enter reference key to get Adv data ");
    } else {
      referenceKey = args[0];
    }

    String payload = createAdvGetRequest(referenceKey);

    System.out.println(
        "------------------------------------------GetAdvRequest-------------------------------------  ");
    Files.write(Paths.get("AdvStoreData.json"), payload.getBytes());
    // HttpClient client = createHttpClient();

    HttpClient client = createHttpClient();

    // HttpClient client = HttpClient.newBuilder()
    // .connectTimeout(Duration.ofSeconds(60))
    // .followRedirects(HttpClient.Redirect.NORMAL)
    // .build();

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(
            "https://api-uat.hdfcbank.com/OBPAPI/com.ofss.fc.cz.hdfc.obp.aadhaarvault.webservice/GetAuxDataRestWrapperService/getAuxData"))
        .header("Content-Type", "application/json")
        .header("apikey", "1zYlb4w9j6KpuGOr8SvVxsVi9G5XGGZCkmT2jyFfy2FFOCH1")
        .timeout(Duration.ofSeconds(60))
        .POST(HttpRequest.BodyPublishers.ofString(payload))
        .build();
    System.out.println("--------------------------GetAdvResponse-----------------------------------------");
    // HttpClientLogger.logRequestBody(request);

    HttpResponse<String> response = client.send(request,
        HttpResponse.BodyHandlers.ofString());

    System.out.println("Status Code: " + response.statusCode());
    Files.write(Paths.get("AdvGetData.json"), response.body().getBytes());
    System.out.println("Response stored in: AdvGetData.json");
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

  private static String createAdvGetRequest(String referenceKey) throws JsonProcessingException {

    SessionContext sessionContext = new SessionContext();
    sessionContext.setChannel("APIGW");
    sessionContext.setUserId("DevUser01");
    sessionContext.setExternalReferenceNo("21903623");
    sessionContext.setBankCode("08");
    sessionContext.setTransactionBranch("089999");

    RequestRetrievalString requestGetString = new RequestRetrievalString("getAuxData", "24", "APS", "153391273149",
        "908767875433",
        "base64");
    HdfcAdvRequest hdfcAdvRequest = new HdfcAdvRequest();
    AadhaarServicesDTO aadhaarServicesDTO = hdfcAdvRequest.new AadhaarServicesDTO(requestGetString);

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