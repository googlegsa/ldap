// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.adaptor.ldap;

import com.google.common.annotations.VisibleForTesting;
import com.google.enterprise.adaptor.AbstractAdaptor;
import com.google.enterprise.adaptor.AdaptorContext;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.StartupException;
import com.google.enterprise.adaptor.Status;
import com.google.enterprise.adaptor.StatusSource;
import com.google.enterprise.adaptor.UserPrincipal;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.InterruptedNamingException;
import javax.naming.NamingException;

/** For getting LDAP content (not just ACLs) into a Google Search Appliance. */
public class LdapAdaptor extends AbstractAdaptor {
  private static final Logger log
      = Logger.getLogger(LdapAdaptor.class.getName());

  /** Charset used in generated HTML responses. */
  private static final Charset CHARSET = Charset.forName("UTF-8");

  /** Call default main for adaptors. */
  public static void main(String[] args) {
    AbstractAdaptor.main(new LdapAdaptor(), args);
  }

  private String defaultNamespace;
  private List<LdapServer> servers = new ArrayList<LdapServer>();
  private long ldapTimeoutInMillis;

  @Override
  public void initConfig(Config config) {
    config.addKey("ldap.servers", null);
    config.addKey("ldap.readTimeoutSecs", "90");
    config.addKey("adaptor.namespace", "");
  }

  @Override
  public void init(AdaptorContext context) throws Exception {
    Config config = context.getConfig();
    defaultNamespace = config.getValue("adaptor.namespace");
    log.config("default namespace: " + defaultNamespace);
    ldapTimeoutInMillis = parseReadTimeoutInMillis(
        config.getValue("ldap.readTimeoutSecs"));

    /* TODO(myk): consider adding incremental crawls.  Then we can add the line:
    context.setPollingIncrementalLister(this); */
    List<Map<String, String>> serverConfigs
        = config.getListOfConfigs("ldap.servers");
    servers.clear();  // in case init gets called again
    for (Map<String, String> singleServerConfig : serverConfigs) {
      /* TODO(myk): see if we need to parse connectorManager */
      /* TODO(myk): see if we need to parse connectorName */
      /* TODO(myk): see if we need to parse Type */
      String host = singleServerConfig.get("host");
      if (host == null || host.isEmpty()) {
        throw new InvalidConfigurationException("host not specified for "
            + "ldap.servers item " + singleServerConfig.get("name"));
      }
      int port = 389;
      Method method = Method.STANDARD;
      if (singleServerConfig.containsKey("connectionMethod")) {
        String methodStr = singleServerConfig.get("connectionMethod")
            .toLowerCase();
        if ("ssl".equals(methodStr)) {
          method = Method.SSL;
          port = 636;
        } else if (!"standard".equals(methodStr)) {
          throw new InvalidConfigurationException("invalid connectionMethod: "
              + methodStr + " specified for host " + host);
        }
      }
      if (singleServerConfig.containsKey("port")) {
        port = Integer.parseInt(singleServerConfig.get("port"));
      }
      /* TODO(myk): parse authenticationType, allow Anonymous */
      String principal = singleServerConfig.get("ldapBindingDistinguishedName");
      if (principal.isEmpty()) {
        throw new InvalidConfigurationException("ldapBindingDistinguishedName "
              + "not specified for host " + host);
      }
      String passwd = singleServerConfig.get("ldapBindingPassword");
      if (null != passwd) {
        passwd = context.getSensitiveValueDecoder().decodeValue(passwd);
      }
      if (passwd == null || passwd.isEmpty()) {
        throw new InvalidConfigurationException("ldapBindingPassword not "
              + "specified for host " + host);
      }
      String baseDN = singleServerConfig.get("ldapSearchBase");
      if (baseDN == null || baseDN.isEmpty()) {
        throw new InvalidConfigurationException("ldapSearchBase not specified "
              + "for host " + host);
      }
      String userFilter = singleServerConfig.get("userFilter");
      if (userFilter == null || userFilter.isEmpty()) {
        throw new InvalidConfigurationException("userFilter not specified for "
              + "host " + host);
      }
      String attributes = singleServerConfig.get("attributes");
      if (attributes == null || attributes.isEmpty()) {
        throw new InvalidConfigurationException("attributes not specified for "
              + "host " + host);
      }
      String globalNamespace = singleServerConfig.get("globalNamespace");
      if (globalNamespace == null || globalNamespace.isEmpty()) {
        globalNamespace = defaultNamespace;
      }
      String localNamespace = singleServerConfig.get("localNamespace");
      if (localNamespace == null || localNamespace.isEmpty()) {
        localNamespace = defaultNamespace;
      }
      int docsPerMinute = 1000; // "documents" (people) read in per minute
      if (singleServerConfig.containsKey("docsPerMinute")) {
        docsPerMinute = Integer.parseInt(
            singleServerConfig.get("docsPerMinute"));
      }
      boolean disableTraversal = Boolean.parseBoolean(
          singleServerConfig.get("disableTraversal"));
      // TODO(myk): allow Widget View, Detailed View, Detailed View with
      // Dynamic Navigation -- most likely just using three config variables.
      String displayTemplate = singleServerConfig.get("displayTemplate");
      if (displayTemplate == null || displayTemplate.isEmpty()) {
        displayTemplate = LdapPerson.allAttributesDisplayTemplate(attributes);
      }
      validateDisplayTemplate(displayTemplate);

      LdapServer ldapServer = newLdapServer(host,
          singleServerConfig.get("name"), method, port, principal, passwd,
          baseDN, userFilter, attributes, globalNamespace, localNamespace,
          docsPerMinute, disableTraversal, ldapTimeoutInMillis,
          displayTemplate);
      ldapServer.initialize();
      servers.add(ldapServer);
      Map<String, String> dup = new TreeMap<String, String>(singleServerConfig);
      dup.put("ldapBindingPassword", "XXXXXX");  // hide password
      log.config("LDAP server spec: " + dup);
    }
    // add a new StatusSource to the Dashboard
    context.addStatusSource(new AttributeValidationStatusSource(config,
        servers));
  }

  /**
   * This method exists specifically to be overwritten in the test class, in
   * order to inject a version of LdapServer that uses mocks.
   */
  @VisibleForTesting
  LdapServer newLdapServer(String host, String nick, Method method, int port,
      String principal, String passwd, String baseDN, String userFilter,
      String attributes, String globalNamespace, String localNamespace,
      int docsPerMinute, boolean disableTraversal, long ldapTimeoutInMillis,
      String displayTemplate) throws StartupException {
    return new LdapServer(host, nick, method, port, principal, passwd, baseDN,
        userFilter, attributes, globalNamespace, localNamespace, docsPerMinute,
        disableTraversal, ldapTimeoutInMillis, displayTemplate);
  }

  private static long parseReadTimeoutInMillis(String timeInSeconds)
      throws InvalidConfigurationException {
    if (timeInSeconds.equals("0") || timeInSeconds.trim().equals("")) {
      timeInSeconds = "90";
      log.config("ldap.readTimeoutSecs set to default of 90 sec.");
    }
    try {
      if (Long.parseLong(timeInSeconds) <= 0) {
        throw new InvalidConfigurationException("invalid (too small) value for "
            + "ldap.readTimeoutSecs: " + timeInSeconds);
      }
      return 1000L * Long.parseLong(timeInSeconds);
    } catch (NumberFormatException e) {
      throw new InvalidConfigurationException("invalid (non-numeric) value for "
          + "ldap.readTimeoutSecs: " + timeInSeconds);
    }
  }

  /**
   * This method validates the <code>displayTemplate</code> configuration value,
   * making sure that the braces balance (and that at most one brace at a time
   * is opened).  Additional validation (that each attribute inside the braces
   * is actually fetched from LDAP) is done inside the
   * <code>LdapServer.search()</code> routine.
   */
  @VisibleForTesting
  static void validateDisplayTemplate(String template)
      throws InvalidConfigurationException {
    int braceLevel = 0;
    int position = 0;
    for (char c : template.toCharArray()) {
      position++;
      if (c == '{') {
        braceLevel++;
        if (braceLevel > 1) {
          break; // and throw exception, below
        }
      } else if (c == '}') {
        braceLevel--;
        if (braceLevel < 0) {
          break; // and throw exception, below
        }
      }
    }
    if (braceLevel != 0) {
      throw new InvalidConfigurationException("invalid value for "
          + "displayTemplate: " + template + " found at position " + position);
    }
  }

  /** Crawls/pushes ids of all people from all LDAP Servers. */
  @Override
  public void getDocIds(DocIdPusher pusher) throws InterruptedException,
      IOException {
    log.entering("LdapAdaptor", "getDocIds");
    String badHosts = ""; // built up as we run into errors
    NamingException lastException = null;
    for (int serverNumber = 0; serverNumber < servers.size(); serverNumber++) {
      LdapServer server = servers.get(serverNumber);
      try {
        server.ensureConnectionIsCurrent();
        Set<LdapPerson> entities = server.scanAll();
        ArrayList<DocId> docIds = new ArrayList<DocId>();
        log.fine("received " + entities.size() + " entities from server");
        for (LdapPerson person : entities) {
          docIds.add(makeDocId(serverNumber, person.getDn()));
        }
        log.fine("About to push " + docIds.size() + " docIds for host "
            + server.getHostName() + ".");
        pusher.pushDocIds(docIds);
        log.finer("Done with push of " + docIds.size() + " docIds for host "
            + server.getHostName() + ".");
      } catch (NamingException ne) {
        String host = server.getHostName();
        badHosts += "," + host;
        lastException = ne;
        log.log(Level.WARNING, "Could not get entitites from " + host, ne);
        continue; // just log for now; throw exception at very end.
      }
    }
    log.exiting("LdapAdaptor", "getDocIds", (lastException != null));
    if (lastException != null) {
      throw new IOException("Could not get entities from the following "
          + "server(s): " + badHosts.substring(1), lastException);
    }
  }

  private DocId makeDocId(int serverNumber, String dn) {
    return new DocId("server=" + serverNumber + "/" + dn);
  }

  private int docIdToLdapServerNumber(DocId docId) {
    String serverAndDn = docId.getUniqueId();
    if (serverAndDn.startsWith("server=")) {
      int equals = serverAndDn.indexOf("=");
      int slash = serverAndDn.indexOf("/");
      if (slash > 0) {
        int serverNumber = Integer.valueOf(
            serverAndDn.substring(equals + 1, slash));
        if (serverNumber < servers.size() && serverNumber >= 0) {
          return serverNumber;
        }
      }
    }
    throw new IllegalArgumentException("invalid DocId: " + docId);
  }

  private String docIdToDn(DocId docId) {
    String serverAndDn = docId.getUniqueId();
    if (serverAndDn.startsWith("server=")) {
      int equals = serverAndDn.indexOf("=");
      int slash = serverAndDn.indexOf("/");
      if (slash > 0) {
        int serverNumber = Integer.valueOf(serverAndDn.substring(equals + 1,
            slash));
        String dn = serverAndDn.substring(slash + 1);
        if (serverNumber < servers.size() && serverNumber >= 0) {
          return dn;
        }
      }
    }
    throw new IllegalArgumentException("invalid DocId: " + docId);
  }

  @Override
  public void getDocContent(Request req, Response resp) throws IOException {
    log.entering("LdapAdaptor", "getDocContent", new Object[] {req, resp});
    DocId id = req.getDocId();
    int serverNumber = docIdToLdapServerNumber(id);
    LdapServer server = servers.get(serverNumber);
    String dn = docIdToDn(id);

    if (!id.equals(makeDocId(serverNumber, dn))) {
      log.warning(id + " is not a valid id generated by this adaptor.");
      resp.respondNotFound();
      return;
    }

    LdapPerson fetched;
    try {
      fetched = server.fetchOne(dn);
      if (null == fetched) {
        log.finer("No results found for DN " + dn);
        resp.respondNotFound();
        log.exiting("LdapAdaptor", "getDocContent", 0);
        return;
      }
      InputStream input = new ByteArrayInputStream(fetched.asDoc(
          server.getDisplayTemplate()).getBytes(CHARSET));
      resp.setContentType("text/html; charset=" + CHARSET.name());
      IOHelper.copyStream(input, resp.getOutputStream());
      log.exiting("LdapAdaptor", "getDocContent", 1);
    } catch (InterruptedNamingException e) {
      log.exiting("LdapAdaptor", "getDocContent", 2);
      throw new IOException(e);
    }
  }

  private static class AttributeValidationStatusSource implements StatusSource {

    private final Config config;
    private final Locale locale = Locale.getDefault();
    private final List<LdapServer> servers;

    public AttributeValidationStatusSource(Config config,
        List<LdapServer> servers) {
      this.config = config;
      this.servers = servers;
    }

    @Override
    public String getName(Locale locale) {
      return Translation.STATUS_ATTRIBUTE_VALIDATION.toString(locale);
    }

    @Override
    public Status retrieveStatus() {
      TranslationStatus aggregateStatus = new TranslationStatus(
          Status.Code.INACTIVE, Translation.STATUS_ATTRIBUTE_VALIDATION_EMPTY);
      for (int counter = 0; counter < servers.size(); counter++) {
        LdapServer server = servers.get(counter);
        TranslationStatus serverStatus = server.getStatus();
        // combine that server's Status with our aggregate.
        Status.Code code = aggregateStatus.getCode();
        if (serverStatus.getCode().compareTo(code) > 0) {
          aggregateStatus.setCode(serverStatus.getCode());
        }
        String message = aggregateStatus.getMessage(locale);
        if ("".equals(message)) {
          message = serverStatus.getMessage(locale);
        } else {
          message += ", " + serverStatus.getMessage(locale);
        }
        aggregateStatus.setMessage(message);
      }
      return aggregateStatus;
    }
  }

  /**
   * Enum for all translation keys. All user-visible messages should exist in
   * our resource bundle and have its key here.
   */
  enum Translation {
    STATUS_ATTRIBUTE_VALIDATION,
    STATUS_ATTRIBUTE_VALIDATION_ALL_FOUND,
    STATUS_ATTRIBUTE_VALIDATION_EMPTY,
    STATUS_ATTRIBUTE_VALIDATION_IN_PROGRESS,
    STATUS_ATTRIBUTE_VALIDATION_NOT_ALL_FOUND,
    STATUS_ATTRIBUTE_VALIDATION_USED_NOT_FETCHED,
    ;

    /**
     * @throws java.util.MissingResourceException if it could not find a string
     *   for the default locale
     */
    @Override
    public String toString() {
      return toString(Locale.getDefault());
    }

    /**
     * @throws java.util.MissingResourceException if it could not find a string
     *   for the provided {@code locale}
     */
    public String toString(Locale locale) {
      String localeClassStr
          = "com.google.enterprise.adaptor.ldap.TranslationStrings";
      return ResourceBundle.getBundle(localeClassStr, locale).getString(name());
    }

    /**
     * @throws java.util.MissingResourceException if it could not find a string
     *   for the default locale
     */
    public String toString(Object... params) {
      return toString(Locale.getDefault(), params);
    }

    /**
     * @throws java.util.MissingResourceException if it could not find a string
     *   for the provided {@code locale}
     */
    public String toString(Locale locale, Object... params) {
      String translation = toString(locale);
      return new MessageFormat(translation, locale)
          .format(params, new StringBuffer(), null).toString();
    }
  }

  /**
   * Nearly a copy of the Library version -- messageAsString/setMessage/setCode
   * added.
   */
  static class TranslationStatus implements Status {
    private Code code;
    private final Translation message;
    private final Object[] params;
    private String messageAsString = null;

    public TranslationStatus(Code code) {
      this(code, null);
    }

    public TranslationStatus(Code code, Translation message) {
      this(code, message, new Object[] {});
    }

    public TranslationStatus(Code code, Translation message, Object... params) {
      if (code == null) {
        throw new NullPointerException("Code must not be null");
      }
      this.code = code;
      this.message = message;
      this.params = params;
    }

    @Override
    public Code getCode() {
      return code;
    }

    public void setCode(Code code) {
      this.code = code;
    }

    public void setMessage(String messageAsString) {
      this.messageAsString = messageAsString;
    }

    @Override
    public String getMessage(Locale locale) {
      if (null != messageAsString) {
        return messageAsString;
      }
      return message == null ? null : message.toString(locale, params);
    }
  }

}
