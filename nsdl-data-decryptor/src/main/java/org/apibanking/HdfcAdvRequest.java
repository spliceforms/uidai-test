package org.apibanking;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

public class HdfcAdvRequest {

  @JsonProperty("AadhaarServicesDTO")
  private AadharService aadhaarServicesDTO;
  private SessionContext sessionContext;

  // Getters and Setters
  public AadharService getAadhaarServicesDTO() {
    return aadhaarServicesDTO;
  }

  public void setAadhaarServicesDTO(AadharService aadhaarServicesDTO) {
    this.aadhaarServicesDTO = aadhaarServicesDTO;
  }

  public SessionContext getSessionContext() {
    return sessionContext;
  }

  public void setSessionContext(SessionContext sessionContext) {
    this.sessionContext = sessionContext;
  }

  @JsonSerialize
  public class AadhaarServicesDTO extends AadharService {
    RequestRetrievalString requestString;

    public AadhaarServicesDTO(RequestRetrievalString requestString) {
      this.requestString = requestString;
    }

    public RequestRetrievalString getRequestString() {
      return requestString;
    }

    public void setRequestString(RequestRetrievalString requestString) {
      this.requestString = requestString;
    }

  }

  public class AadhaarServicessDTO extends AadharService {
    RequestStoreString requestString;

    public AadhaarServicessDTO(RequestStoreString requestString) {
      this.requestString = requestString;
    }

    public RequestStoreString getRequestString() {
      return requestString;
    }

    public void setRequestString(RequestStoreString requestString) {
      this.requestString = requestString;
    }

  }

  public record RequestRetrievalString(
      String request, String appId,
      String appName, String referenceKey,
      String type,
      String encodingType) {
  }

  public record RequestStoreString(
      String request,
      String appId,
      String appName,
      String aadhaarNo,
      String primaryData,
      List<AuxData> auxData) {
  }

  public record AuxData(
      String type,
      String data,
      String encodingType) {
  }
}