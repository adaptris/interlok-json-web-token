package com.adaptris.core.jwt;

import com.adaptris.annotation.AdapterComponent;
import com.adaptris.annotation.AdvancedConfig;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.annotation.InputFieldHint;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.ServiceException;
import com.adaptris.core.ServiceImp;
import com.adaptris.util.KeyValuePair;
import com.adaptris.util.KeyValuePairSet;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import java.util.Date;
import java.util.UUID;

@XStreamAlias("jwt-creator")
@AdapterComponent
@ComponentProfile(summary = "Create a JSON Web Token", tag = "jwt,create,json,web,token", since = "3.11.1")
@DisplayOrder(order = {"id", "issuer", "subject", "audience", "issuedAt", "expiration", "notBefore", "secret", "customClaims"})
public class JWTCreator extends ServiceImp {
  @Valid
  @AdvancedConfig(rare = true)
  private String id;
  @NotNull
  @Valid
  @InputFieldHint(expression = true)
  private String issuer;
  @NotNull
  @Valid
  @InputFieldHint(expression = true)
  private String subject;
  @NotNull
  @Valid
  @InputFieldHint(expression = true)
  private String audience;
  @Valid
  @AdvancedConfig(rare = true)
  private Date issuedAt;
  @NotNull
  @Valid
  private Date expiration;
  @NotNull
  @Valid
  private Date notBefore;
  @NotNull
  @Valid
  @InputFieldHint(expression = true)
  private String secret;
  @Valid
  @AdvancedConfig
  private KeyValuePairSet customClaims;

  /**
   * <p>
   * Apply the service to the message.
   * </p>
   *
   * @param message the <code>AdaptrisMessage</code> to process
   * @throws ServiceException wrapping any underlying <code>Exception</code>s
   */
  @Override
  public void doService(AdaptrisMessage message) {
    JwtBuilder builder = Jwts.builder().setSubject(message.resolve(subject)).setAudience(message.resolve(audience)).setNotBefore(notBefore).setIssuer(message.resolve(issuer)).setExpiration(expiration).setIssuedAt(issuedAt != null ? issuedAt : new Date()).setId(id != null ? id : UUID.randomUUID().toString()).signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(message.resolve(secret))));
    if (customClaims != null) {
      for (KeyValuePair claim : customClaims) {
        builder.claim(claim.getKey(), claim.getValue());
      }
    }
    message.setContent(builder.compact(), message.getContentEncoding());
  }

  /**
   * {@inheritDoc}.
   */
  @Override
  protected void initService() {
    /* unused */
  }

  /**
   * {@inheritDoc}.
   */
  @Override
  protected void closeService() {
    /* unused */
  }

  /**
   * Prepare for initialisation.
   */
  @Override
  public void prepare() {
    /* unused */
  }

  public String getId() {
    return this.id;
  }

  public void setId(final String id) {
    this.id = id;
  }

  public String getIssuer() {
    return this.issuer;
  }

  public void setIssuer(final String issuer) {
    this.issuer = issuer;
  }

  public String getSubject() {
    return this.subject;
  }

  public void setSubject(final String subject) {
    this.subject = subject;
  }

  public String getAudience() {
    return this.audience;
  }

  public void setAudience(final String audience) {
    this.audience = audience;
  }

  public Date getIssuedAt() {
    return this.issuedAt;
  }

  public void setIssuedAt(final Date issuedAt) {
    this.issuedAt = issuedAt;
  }

  public Date getExpiration() {
    return this.expiration;
  }

  public void setExpiration(final Date expiration) {
    this.expiration = expiration;
  }

  public Date getNotBefore() {
    return this.notBefore;
  }

  public void setNotBefore(final Date notBefore) {
    this.notBefore = notBefore;
  }

  public String getSecret() {
    return this.secret;
  }

  public void setSecret(final String secret) {
    this.secret = secret;
  }

  public KeyValuePairSet getCustomClaims() {
    return this.customClaims;
  }

  public void setCustomClaims(final KeyValuePairSet customClaims) {
    this.customClaims = customClaims;
  }
}
