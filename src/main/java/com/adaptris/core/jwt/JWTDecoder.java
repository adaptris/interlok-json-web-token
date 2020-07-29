package com.adaptris.core.jwt;

import com.adaptris.annotation.AdapterComponent;
import com.adaptris.annotation.ComponentProfile;
import com.adaptris.annotation.DisplayOrder;
import com.adaptris.core.AdaptrisMessage;
import com.adaptris.core.ServiceException;
import com.adaptris.core.ServiceImp;
import com.adaptris.core.jwt.secrets.SecretConfigurator;
import com.adaptris.interlok.config.DataInputParameter;
import com.adaptris.interlok.config.DataOutputParameter;
import com.thoughtworks.xstream.annotations.XStreamAlias;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParserBuilder;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import lombok.Setter;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * This service provides a way to decode a JSON Web Token.
 *
 * <pre>{@code
 *    <jwt-encode>
 *        <unique-id>mad-lalande</unique-id>
 *        <secret class="constant-data-input-parameter">
 *            <value>base64 encoded secret</value>
 *        </secret>
 *        <jwt-string class="string-payload-input-parameter"/>  <!-- The Base64 encoded JWT string -->
 *        <header class="string-payload-output-parameter"/>     <!-- The JSON header -->
 *        <claims class="string-payload-output-parameter"/>     <!-- The JSON message body -->
 *    </jwt-encode>
 * }</pre>
 *
 * @author aanderson
 * @config jwt-decode
 */
@XStreamAlias("jwt-decode")
@AdapterComponent
@ComponentProfile(summary = "Encode a header and body to a JSON Web Token", tag = "jwt,decode,json,web,token", since="3.11.1")
@DisplayOrder(order = { "jwtString", "secret", "header", "claims" })
public class JWTDecoder extends ServiceImp
{
  private static transient Logger log = LoggerFactory.getLogger(JWTDecoder.class);

  @NotNull
  @Valid
  @Getter
  @Setter
  private DataInputParameter<String> jwtString;

  @NotNull
  @Valid
  @Getter
  @Setter
  private SecretConfigurator secret;

  @NotNull
  @Valid
  @Getter
  @Setter
  private DataOutputParameter<String> header;

  @NotNull
  @Valid
  @Getter
  @Setter
  private DataOutputParameter<String> claims;

  /**
   * {@inheritDoc}.
   */
  @Override
  public void doService(AdaptrisMessage message) throws ServiceException
  {
    try
    {
      String jwt = jwtString.extract(message);

      JwtParserBuilder builder = Jwts.parserBuilder();
      builder = secret.configure(builder);
      Jws<Claims> jws = builder.build().parseClaimsJws(jwt);

      JSONObject head = new JSONObject(jws.getHeader());
      header.insert(head.toString(), message);

      JSONObject body = new JSONObject(jws.getBody());
      claims.insert(body.toString(), message);
    }
    catch (Exception e)
    {
      log.error("An error occurred during JWT decoding", e);
      throw new ServiceException(e);
    }
  }

  /**
   * {@inheritDoc}.
   */
  @Override
  protected void initService()
  {
    /* unused */
  }

  /**
   * {@inheritDoc}.
   */
  @Override
  protected void closeService()
  {
    /* unused */
  }

  /**
   * {@inheritDoc}.
   */
  @Override
  public void prepare()
  {
    /* unused */
  }
}
