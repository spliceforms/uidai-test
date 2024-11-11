package org.apibanking;

public class SessionContext {
  private String channel;
  private String userId;
  private String externalReferenceNo;
  private String bankCode;
  private String transactionBranch;

  // Getters and Setters
  public String getChannel() {
    return channel;
  }

  public void setChannel(String channel) {
    this.channel = channel;
  }

  public String getUserId() {
    return userId;
  }

  public void setUserId(String userId) {
    this.userId = userId;
  }

  public String getExternalReferenceNo() {
    return externalReferenceNo;
  }

  public void setExternalReferenceNo(String externalReferenceNo) {
    this.externalReferenceNo = externalReferenceNo;
  }

  public String getBankCode() {
    return bankCode;
  }

  public void setBankCode(String bankCode) {
    this.bankCode = bankCode;
  }

  public String getTransactionBranch() {
    return transactionBranch;
  }

  public void setTransactionBranch(String transactionBranch) {
    this.transactionBranch = transactionBranch;
  }
}