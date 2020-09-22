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
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import lombok.Setter;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

/**
 * This service provides a way to encode data as a JSON Web Token.
 *
 * <pre>{@code
 *    <jwt-encode>
 *        <unique-id>mad-lalande</unique-id>
 *        <secret class="constant-data-input-parameter">
 *            <value>base64 encoded secret</value>
 *        </secret>
 *        <header class="string-payload-input-parameter"/>      <!-- The JSON header -->
 *        <claims class="string-payload-input-parameter"/>      <!-- The JSON message body -->
 *        <jwt-output class="string-payload-output-parameter"/> <!-- The base64 encoded JWT string -->
 *    </jwt-encode>
 * }</pre>
 *
 * @author aanderson
 * @config jwt-encode
 */
@XStreamAlias("jwt-encode")
@AdapterComponent
@ComponentProfile(summary = "Encode a header and body to a JSON Web Token", tag = "jwt,encode,json,web,token", since="3.11.1")
@DisplayOrder(order = { "header", "claims", "secret", "generateKey", "keyOutput", "jwtOutput" })
public class JWTEncoder extends ServiceImp
{
  private static transient Logger log = LoggerFactory.getLogger(JWTEncoder.class);

  @NotNull
  @Valid
  @Getter
  @Setter
  private DataInputParameter<String> header;

  @NotNull
  @Valid
  @Getter
  @Setter
  private DataInputParameter<String> claims;

  @NotNull
  @Valid
  @Getter
  @Setter
  private SecretConfigurator secret;

  @NotNull
  @Valid
  @Getter
  @Setter
  private DataOutputParameter<String> jwtOutput;

  /**
   * {@inheritDoc}.
   */
  @Override
  public void doService(AdaptrisMessage message) throws ServiceException
  {
    try
    {
      // might as well ensure we've got valid JSON
      JSONObject head = new JSONObject(header.extract(message));
      JSONObject body = new JSONObject(claims.extract(message));

      JwtBuilder builder = Jwts.builder().setClaims(body.toMap()).setHeader(head.toMap());
      builder = secret.configure(builder);
      String jwt = builder.compact();

      jwtOutput.insert(jwt, message);
    }
    catch (Exception e)
    {
      log.error("An error occurred during JWT encoding", e);
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
