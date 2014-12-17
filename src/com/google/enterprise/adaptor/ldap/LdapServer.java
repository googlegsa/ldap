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
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.StartupException;
import com.google.enterprise.adaptor.Status;

import java.io.IOException;
import java.net.ConnectException;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.InterruptedNamingException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.PagedResultsControl;
import javax.naming.ldap.PagedResultsResponseControl;

/** Client that talks to some LDAP Server. */
class LdapServer {
  private static final Logger log
      = Logger.getLogger(LdapServer.class.getName());

  private LdapContext ldapContext;
  private final SearchControls searchCtls;

  // properties necessary for connection and reconnection
  private Method connectMethod;
  private boolean fullScanCompleted = false;
  private long ldapTimeoutInMillis;
  private String listOfMissingAttributes = null;
  private String listOfUsedButNotFetchedAttributes = null;
  private String password;
  private int port;
  private String principal;
  private final String attributes;
  private final String baseDN;
  private final String displayTemplate;
  private final String hostName;
  private final String nickName;
  private final int docsPerMinute; //TODO(myk): implement this functionality
  private final String userFilter;

  public LdapServer(String hostName, String nickName, Method connectMethod,
      int port, String principal, String password, String baseDN,
      String userFilter, String attributes, int docsPerMinute,
      long ldapTimeoutInMillis, String displayTemplate) {
    this(hostName, nickName, baseDN, userFilter, attributes, docsPerMinute,
        displayTemplate, createLdapContext(hostName, connectMethod, port,
            principal, password, ldapTimeoutInMillis));
    this.connectMethod = connectMethod;
    this.port = port;
    this.principal = principal;
    this.password = password;
    this.ldapTimeoutInMillis = ldapTimeoutInMillis;
  }

  @VisibleForTesting
  LdapServer(String hostName, String nickName, String baseDN, String userFilter,
      String attributes, int docsPerMinute, String displayTemplate,
      LdapContext ldapContext) {
    this.hostName = hostName;
    this.nickName = nickName;
    this.baseDN = baseDN;
    this.userFilter = userFilter;
    this.attributes = attributes;
    this.docsPerMinute = docsPerMinute;
    this.displayTemplate = displayTemplate;
    this.ldapContext = ldapContext;
    searchCtls = new SearchControls();
    searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
  }

  /**
   * Normally called (only) by public constructor and recreateLdapContext().
   */
  private static LdapContext createLdapContext(String hostName,
      Method connectMethod, int port, String principal, String password,
      long ldapTimeoutInMillis) {
    Hashtable<String, String> env = new Hashtable<String, String>();
    if (null == connectMethod || null == hostName
        || null == principal || null == password) {
      throw new NullPointerException();
    }
    if ("".equals(hostName)) {
      throw new IllegalArgumentException("host needs to be non-empty");
    }
    if ("".equals(principal)) {
      throw new IllegalArgumentException("principal needs to be non-empty");
    }
    if ("".equals(password)) {
      throw new IllegalArgumentException("password needs to be non-empty");
    }

    // Use the built-in LDAP support.
    // TODO(myk): See if we can specify a value in the configuration file to
    // allow us to override this, for unit tests.
    env.put(Context.INITIAL_CONTEXT_FACTORY,
        "com.sun.jndi.ldap.LdapCtxFactory");
    // Connecting to configuration naming context is very slow for crawl users
    // in large multidomain environment, which belong to thousands of groups
    env.put("com.sun.jndi.ldap.read.timeout", "" + ldapTimeoutInMillis);
    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    // TODO(myk): allow anonymous authentication
    env.put(Context.SECURITY_PRINCIPAL, principal);
    env.put(Context.SECURITY_CREDENTIALS, password);

    String ldapUrl = connectMethod.protocol() + hostName + ":" + port;
    log.config("LDAP provider url: " + ldapUrl);
    env.put(Context.PROVIDER_URL, ldapUrl);
    try {
      return new InitialLdapContext(env, null);
    } catch (NamingException ne) {
      // display (throw) a "nicer" exception message when we cannot connect.
      // This can be an AuthenticationException (wrong user name or password) or
      // a ConnectException (wrong hostname).
      Throwable cause = ne.getCause();
      boolean replaceException = false;
      boolean abortStartup = false;
      if (cause instanceof ConnectException) {
        ConnectException ce = (ConnectException) cause;
        if (ce.getMessage() != null
            && (ce.getMessage().contains("Connection timed out")
                || ce.getMessage().contains("Connection refused"))) {
          replaceException = true;
        }
      } else if (ne instanceof AuthenticationException) {
        // this is the only exception we flag as a StartupException.
        replaceException = true;
        abortStartup = true;
      } else if (ne instanceof CommunicationException) {
        replaceException = true;
      }
      if (replaceException) {
        String warning = String.format("Cannot connect to server \"%s\" as "
            + "user \"%s\" with the specified password.  Please make sure "
            + "they are specified correctly.  If the LDAP server is currently "
            + "down, please try again later.", hostName, principal);
        if (abortStartup) {
          throw new StartupException(warning, ne);
        } else {
          throw new RuntimeException(warning, ne);
        }
      }
      // wasn't the specific error we're looking for -- rethrow it.
      // <code>RuntimeException</code> is caught by the library, and retried.
      throw new RuntimeException(ne);
    }
  }

  @VisibleForTesting
  void recreateLdapContext() {
    ldapContext = createLdapContext(hostName, connectMethod, port, principal,
        password, ldapTimeoutInMillis);
  }

  /**
   * Connects to the Active Directory server and retrieves LDAP configuration
   * information.
   * <p>This method is used for crawling as well as authorization of credentials
   * against Active Directory.  Calling this method after a connection has been
   * established will refresh the connection attributes.
   */
  public void ensureConnectionIsCurrent()
      throws CommunicationException, NamingException {
    Attributes attributes;
    try {
      attributes = ldapContext.getAttributes("");
    } catch (CommunicationException ce) {
      log.log(Level.FINER,
          "Reconnecting to LdapServer after detecting issue", ce);
      try {
        recreateLdapContext();
      } catch (StartupException se) {
        // authentication issues
        NamingException ne = new NamingException("recreateLdapContext problem");
        ne.setRootCause(se);
        throw ne;
      }
      attributes = ldapContext.getAttributes("");
    } catch (NamingException ne) {
      if (ne.getMessage() != null
          && ne.getMessage().contains("read timed out")) {
        log.log(Level.WARNING, "Read timeout insufficient", ne);
        log.warning("Consider increasing the value of "
            + "``ldap.ldapReadTimeoutSeconds'' in the config file.");
      }
      // rethrow the exception, whether or not we were able to give advice.
      throw(ne);
    }
  }

  public void initialize() throws InvalidConfigurationException {
    try {
      ensureConnectionIsCurrent();
    } catch (NamingException e) {
      throw new RuntimeException(e);
    }
    log.info("Successfully created an Initial LDAP context on domain "
        + hostName + ".");
  }

  /**
   * Searches LDAP repository and creates LdapPerson on each result found
   * @param baseDN baseDN for the search
   * @param filter LDAP filter to restrict results from the LDAP server
   * @param attributes list of attributes to retrieve
   * @param validateAttributes should the attribute list be validated?
   * @return list of entities found
   */
  protected Set<LdapPerson> search(String baseDN, String filter,
      String[] attributes, boolean validateAttributes)
      throws InterruptedNamingException {
    Set<LdapPerson> results = new HashSet<LdapPerson>();
    searchCtls.setReturningAttributes(attributes);
    Set<String> attributesNotYetSeen = new TreeSet<String>();
    Set<String> fetchedAttributes = new TreeSet<String>();
    if (validateAttributes) {
      for (String attr : attributes) {
        fetchedAttributes.add(attr.toLowerCase());
        // ignore "dn", which we treat as an attribute, but isn't really one
        if (!"".equals(attr) && !"dn".equals(attr)) {
          attributesNotYetSeen.add(attr.toLowerCase());
        }
      }
    }
    try {
      Control[] controls = new Control[] {
          new PagedResultsControl(1000 /* page size */,
              false /* criticality */)};
      ldapContext.setRequestControls(controls);
    } catch (IOException e) {
      log.log(Level.WARNING, "Couldn't initialize LDAP paging control. "
          + "Will continue without paging - this can cause issue if there "
          + "are too many users being retrieved.", e);
    } catch (NamingException e) {
      log.log(Level.WARNING, "Couldn't initialize LDAP paging control. "
          + "Will continue without paging - this can cause issue if there "
          + "are too many users being retrieved.", e);
    }
    try {
      ensureConnectionIsCurrent();
      byte[] cookie = null;
      do {
        NamingEnumeration<SearchResult> ldapResults =
            ldapContext.search(baseDN, filter, searchCtls);
        while (ldapResults.hasMoreElements()) {
          SearchResult sr = ldapResults.next();
          try {
            results.add(new LdapPerson(sr));
            // if validating, mark any attribute that was fetched
            if (validateAttributes && !attributesNotYetSeen.isEmpty()) {
              Attributes allAttrs = sr.getAttributes();
              NamingEnumeration<String> idEnumeration = allAttrs.getIDs();
              while (idEnumeration.hasMore()) {
                String id = idEnumeration.next().toLowerCase();
                attributesNotYetSeen.remove(id);
              }
              idEnumeration.close();
            }
          } catch (Exception ex) {
            // It is possible that Search Result returned is missing
            // few attributes required to construct LdapPerson object.
            // Such results will be ignored.
            // This exception is logged and ignored to allow connector to
            // continue crawling otherwise connector can not
            // proceed with traversal.
            log.log(Level.WARNING, "Error Processing Search Result "
                + sr, ex);
          }
        }
        cookie = null;
        Control[] resultResponseControls = ldapContext.getResponseControls();
        for (int i = 0; i < resultResponseControls.length; ++i) {
          if (resultResponseControls[i]
              instanceof PagedResultsResponseControl) {
            cookie = ((PagedResultsResponseControl) resultResponseControls[i])
                .getCookie();
            ldapContext.setRequestControls(new Control[] {
                new PagedResultsControl(1000 /* page size */, cookie,
                    Control.CRITICAL)});
          }
        }
      } while ((cookie != null) && (cookie.length != 0));
    } catch (InterruptedNamingException e) {
      throw e;
    } catch (NamingException e) {
      log.log(Level.WARNING, "", e);
    } catch (IOException e) {
      log.log(Level.WARNING, "Couldn't initialize LDAP paging control. "
          + "Will continue without paging - this can cause issue if there "
          + "are too many users being retrieved.", e);
    }
    if (validateAttributes) {
      // validate all desired attributes (from Adaptor configuration) against
      // those observed (from actual LDAP results).
      if (attributesNotYetSeen.isEmpty()) {
        listOfMissingAttributes = null;
      } else {
        listOfMissingAttributes = "";
        for (String id : attributesNotYetSeen) {
          if ("".equals(listOfMissingAttributes)) {
            listOfMissingAttributes = id;
          } else {
            listOfMissingAttributes += ", " + id;
          }
        }
      }
      // validate all attributes to be displayed (from one configuration
      // variable) against all to be fetched (another configuration variable).
      String oneAttributeName;
      int index = -1;
      int left = 0;
      for (char c : displayTemplate.toCharArray()) {
        index++;
        if (c == '{') {
          left = index;
        } else if (c == '}') {
          oneAttributeName = displayTemplate.substring(left + 1, index);
          if (!fetchedAttributes.contains(oneAttributeName.toLowerCase())) {
            // add the newly-found "bad" attribute to our error list
            if (null == listOfUsedButNotFetchedAttributes) {
              listOfUsedButNotFetchedAttributes = oneAttributeName;
            } else {
              listOfUsedButNotFetchedAttributes += ", " + oneAttributeName;
            }
          }
        }
      }
    }
    return results;
  }

  /**
   * Searches LDAP repository and creates LdapPerson on each result found
   * @return list of entities found
   */
  public Set<LdapPerson> scanAll() throws InterruptedNamingException {
    //TODO(myk): support incremental scan by also allowing an attribute for
    // last modification time

    // Each time we scan all, we update a Status indicator on the Dashboard
    // to let the admin know if there is some desired Attribute that is not
    // being fetched.
    Set<LdapPerson> results = this.search(baseDN, userFilter,
        attributes.split(","), true);
    fullScanCompleted = true;
    return results;
  }

  /**
   * Fetches one specific LDAP Person from the repository
   * @param dn the Person-specific DN
   * @return the LDAP Person at the specified DN, or <code>null</code> if
   * not found.
   */
  public LdapPerson fetchOne(String dn) throws InterruptedNamingException {
    log.entering("LdapServer", "fetchOne", new Object[] { nickName, dn });

    Set<LdapPerson> results = this.search(dn, userFilter,
        attributes.split(","), false);

    if (results.size() == 0) {
      log.exiting("LdapServer", "fetchOne", 0);
      return null;
    } else if (results.size() == 1) {
      Object[] personArray = (Object[]) results.toArray();
      Object person = personArray[0];
      if (person instanceof LdapPerson) {
        log.exiting("LdapServer", "fetchOne", person);
        return (LdapPerson) person;
      } else {
        log.exiting("LdapServer", "fetchOne", 1);
        throw new IllegalArgumentException("non-LdapPerson found at " + dn
            + ":" + person.toString());
      }
    } else {
      log.exiting("LdapServer", "fetchOne", 2);
      throw new IllegalArgumentException("More than one person found at "
          + dn + " : " + results.size() + " results.");
    }
  }

  @Override
  public String toString() {
    return "[" + hostName + "] ";
  }

  public String getHostName() {
    return hostName;
  }

  public String getDisplayTemplate() {
    return displayTemplate;
  }

  public LdapAdaptor.TranslationStatus getStatus() {
    if (!fullScanCompleted) {
      return new LdapAdaptor.TranslationStatus(Status.Code.UNAVAILABLE,
        LdapAdaptor.Translation.STATUS_ATTRIBUTE_VALIDATION_IN_PROGRESS,
        nickName);
    }
    if (listOfUsedButNotFetchedAttributes != null) {
      return new LdapAdaptor.TranslationStatus(Status.Code.ERROR,
        LdapAdaptor.Translation.STATUS_ATTRIBUTE_VALIDATION_USED_NOT_FETCHED,
        nickName, listOfUsedButNotFetchedAttributes);
    }
    if (listOfMissingAttributes != null) {
      return new LdapAdaptor.TranslationStatus(Status.Code.WARNING,
        LdapAdaptor.Translation.STATUS_ATTRIBUTE_VALIDATION_NOT_ALL_FOUND,
        nickName, listOfMissingAttributes);
    }
    return new LdapAdaptor.TranslationStatus(Status.Code.NORMAL,
      LdapAdaptor.Translation.STATUS_ATTRIBUTE_VALIDATION_ALL_FOUND,
      nickName);
  }
}
