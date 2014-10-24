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

import static org.junit.Assert.*;

import com.google.enterprise.adaptor.Acl;
import com.google.enterprise.adaptor.Adaptor;
import com.google.enterprise.adaptor.Config;
import com.google.enterprise.adaptor.DocId;
import com.google.enterprise.adaptor.DocIdPusher;
import com.google.enterprise.adaptor.GroupPrincipal;
import com.google.enterprise.adaptor.IOHelper;
import com.google.enterprise.adaptor.InvalidConfigurationException;
import com.google.enterprise.adaptor.Principal;
import com.google.enterprise.adaptor.Request;
import com.google.enterprise.adaptor.Response;
import com.google.enterprise.adaptor.Status;
import com.google.enterprise.adaptor.TestHelper;

import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.naming.CommunicationException;
import javax.naming.InterruptedNamingException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

/**
  * Unit tests for methods in LdapAdaptor and all its non-private subclasses.
  */
public class LdapAdaptorTest {
  @Rule
  public ExpectedException thrown = ExpectedException.none();

  // tests for methods in the main LdapAdaptor class

  @Test
  public void testFakeAdaptorInitCompletes() throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    // pushGroupDefinitions calls AdAdaptor.init() with the specified config.
  }

  @Test
  public void testFakeAdaptorInitThrowsICEWhenHostUnspecified()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.host");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("host not specified"));
      assertTrue(ice.getMessage().endsWith("item server1"));
    }
    configEntries.put("ldap.servers.server1.host", "");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("host not specified"));
      assertTrue(ice.getMessage().endsWith("item server1"));
    }
  }

  @Test
  public void testFakeAdaptorInitOKWhenConnectionMethodDefaultValue()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.put("ldap.servers.server1.connectionMethod", "invalid");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("invalid connectionMethod:"));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
    configEntries.remove("ldap.servers.server1.connectionMethod");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
    // above should now work.
  }

  @Test
  public void testFakeAdaptorInitOKWhenPortDefaultValue() throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.port");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
  }

  @Test
  public void testFakeAdaptorInitThrowsICEWhenPrincipalMissingOrEmpty()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.ldapBindingDistinguishedName");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("ldapBindingDistinguishedName "));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
    configEntries.put("ldap.servers.server1.ldapBindingDistinguishedName", "");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("ldapBindingDistinguishedName "));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
  }

  @Test
  public void testFakeAdaptorInitThrowsICEWhenPasswordMissingOrEmpty()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.ldapBindingPassword");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("ldapBindingPassword not "));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
    configEntries.put("ldap.servers.server1.ldapBindingPassword", "");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("ldapBindingPassword not "));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
  }

  @Test
  public void testFakeAdaptorInitThrowsICEWhenLdapSearchBaseMissingOrEmpty()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.ldapSearchBase");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("ldapSearchBase not specified "));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
    configEntries.put("ldap.servers.server1.ldapSearchBase", "");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("ldapSearchBase not specified "));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
  }

  @Test
  public void testFakeAdaptorInitThrowsICEWhenUserFilterMissingOrEmpty()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.userFilter");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("userFilter not specified "));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
    configEntries.put("ldap.servers.server1.userFilter", "");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("userFilter not specified "));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
  }

  @Test
  public void testFakeAdaptorInitThrowsICEWhenAttributesMissingOrEmpty()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.attributes");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("attributes not specified "));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
    configEntries.put("ldap.servers.server1.attributes", "");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("attributes not specified "));
      assertTrue(ice.getMessage().endsWith("for host localhost"));
    }
  }

  @Test
  public void testFakeAdaptorInitOKWhenGlobalNamespaceDefaultValue()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.globalNamespace");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
    configEntries.put("ldap.servers.server1.globalNamespace", "");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
  }

  @Test
  public void testFakeAdaptorInitOKWhenLocalNamespaceDefaultValue()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.localNamespace");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
    configEntries.put("ldap.servers.server1.localNamespace", "");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
  }

  @Test
  public void testFakeAdaptorInitOKWhenDocsPerMinuteDefaultValue()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.docsPerMinute");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
  }

  @Test
  public void testFakeAdaptorInitOKWhenDisplayTemplateDefaultValue()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.remove("ldap.servers.server1.displayTemplate");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
    configEntries.put("ldap.servers.server1.displayTemplate", "");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
  }

  @Test
  public void testFakeAdaptorInitOKWhenReadTimeoutSecsDefaultValue()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.put("ldap.readTimeoutSecs", "");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
    configEntries.put("ldap.readTimeoutSecs", "0");
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
        /*fullPush=*/ true, /*init=*/ true);
  }

  @Test
  public void testFakeAdaptorInitThrowsICEWhenReadTimeoutSecsInvalid()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntries();
    configEntries.put("ldap.readTimeoutSecs", "-1");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("invalid (too small) value"));
    }
    configEntries.put("ldap.readTimeoutSecs", "bogus");
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (InvalidConfigurationException ice) {
      assertTrue(ice.getMessage().startsWith("invalid (non-numeric) value"));
    }
  }

  @Test
  public void testValidateDisplayTemplate_allTests() throws Exception {
    // none of these should throw an exception
    FakeAdaptor.validateDisplayTemplate("");
    FakeAdaptor.validateDisplayTemplate("text with no braces");
    FakeAdaptor.validateDisplayTemplate("text with {one long brace} sequence");
    FakeAdaptor.validateDisplayTemplate("{text} {with} {balanced} {braces}");
    try {
      FakeAdaptor.validateDisplayTemplate("{brace that doesn't end");
    } catch (InvalidConfigurationException ice) {
      assertEquals("invalid value for displayTemplate: {brace that doesn't end "
          + "found at position 23", ice.getMessage());
    }
    try {
      FakeAdaptor.validateDisplayTemplate("brace that doesn't start}");
    } catch (InvalidConfigurationException ice) {
      assertEquals("invalid value for displayTemplate: brace that doesn't "
          + "start} found at position 25", ice.getMessage());
    }
    try {
      FakeAdaptor.validateDisplayTemplate("{{double braces}}");
    } catch (InvalidConfigurationException ice) {
      assertEquals("invalid value for displayTemplate: {{double braces}} "
          + "found at position 2", ice.getMessage());
    }
  }

  @Test
  public void testGetDocIdsNormal() throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntriesForOneServer();
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    // the above calls AdAdaptor.init() with the specified config as well as
    // calling getDocIds.
    assertEquals(1, pusher.getRecords().size());
    String expectedDocId="server=0/cn=name\\ under,cn=name\\ under,basedn";
    String expectedRecord="Record(docid=" + expectedDocId + ",delete=false,"
        + "lastModified=null,resultLink=null,crawlImmediately=false,crawlOnce="
        + "false,lock=false)";
    assertEquals(expectedRecord, pusher.getRecords().get(0).toString());

    // reset the pusher so that it can be used again to test idempotence.
    pusher.reset();
    assertEquals(0, pusher.getRecords().size());

    // testing idempotent call to getDocIds.
    ldapAdaptor.getDocIds(pusher);
    assertEquals(1, pusher.getRecords().size());
    assertEquals(expectedRecord, pusher.getRecords().get(0).toString());
  }

  @Test
  public void testGetDocIdsNamingException() throws Exception {
    final MockLdapContext ldapContext = new MockLdapContext();
    final LdapAdaptor ldapAdaptor = new LdapAdaptor() {
      @Override
      LdapServer newLdapServer(String host, String nick, Method method,
          int port, String principal, String passwd, String baseDN,
          String userFilter, String attributes, String globalNamespace,
          String localNamespace, int docsPerMinute, boolean disableTraversal,
          long ldapTimeoutInMillis, String displayTemplate) {

        return new LdapServer(host, nick, baseDN, userFilter, attributes,
            globalNamespace, localNamespace, docsPerMinute, disableTraversal,
            displayTemplate, ldapContext) {
          @Override
          void recreateLdapContext() {
            // leave ldapContext unchanged
          }
          @Override
          public void ensureConnectionIsCurrent()
              throws CommunicationException, NamingException {
            // do nothing
          }
          @Override
          public Set<LdapPerson> scanAll() throws InterruptedNamingException {
            throw new InterruptedNamingException("INE");
          }
        };
      }
    };
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntriesForOneServer();
    try {
      pushGroupDefinitions(ldapAdaptor, configEntries, pusher,
          /*fullPush=*/ true, /*init=*/ true);
    } catch (IOException ioe) {
      assertEquals("Could not get entities from the following server(s): "
          + "localhost", ioe.getMessage());
      assertTrue(ioe.getCause() instanceof NamingException);
      NamingException ne = (NamingException) ioe.getCause();
      assertTrue(ne.getMessage().contains("INE"));
    }
    assertEquals(0, pusher.getRecords().size());
  }

  @Test
  public void testGetDocContent_InvalidDocIds() throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntriesForOneServer();
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    // the above calls AdAdaptor.init() with the specified config.
    assertEquals(1, pusher.getRecords().size());
    MockResponse response = new MockResponse();
    String[] docIdsToTest = new String[] {
        "" /* empty */,
        "server=0" /* no slash */,
        "server=1/dn" /* server number too big */,
        "server=-1/dn" /* server number too small */
    };
    for (String docId : docIdsToTest) {
      try {
        ldapAdaptor.getDocContent(new MockRequest(new DocId(docId)), response);
        fail("did not catch expected IllegalArgumentException");
      } catch (IllegalArgumentException iae) {
        assertEquals("invalid DocId: DocId(" + docId + ")", iae.getMessage());
      }
    }
  }

  // not included in testGetDocContent_InvalidDocIds() because this case does
  // not throw an exception, it simply returns a 404.
  @Test
  public void testGetDocContentInvalidDocId_serverNumberHasLeadingZero()
      throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntriesForOneServer();
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    // the above calls AdAdaptor.init() with the specified config.
    assertEquals(1, pusher.getRecords().size());
    MockResponse response = new MockResponse();
    ldapAdaptor.getDocContent(new MockRequest(
        // below is the "expected DocID" except for the additional 0 in server.
        new DocId("server=00/cn=name\\ under,basedn")), response);
    assertTrue(response.notFound);
  }

  @Test
  public void testGetDocContentNormal() throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntriesForOneServer();
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    // the above calls AdAdaptor.init() with the specified config.
    assertEquals(1, pusher.getRecords().size());
    String expectedDocId="server=0/cn=name\\ under,basedn";
    String expectedRecord="Record(docid=server=0/cn=name\\ under,cn=name\\ "
        + "under,basedn,delete=false,lastModified=null,resultLink=null,"
        + "crawlImmediately=false,crawlOnce=false,lock=false)";
    assertEquals(expectedRecord, pusher.getRecords().get(0).toString());
    pusher.reset();
    MockResponse response = new MockResponse();
    ldapAdaptor.getDocContent(new MockRequest(new DocId(expectedDocId)),
        response);
    assertFalse(response.notFound);
    assertEquals("text/html; charset=UTF-8", response.contentType);
    // note that the displayTemplate is simply: "cn: {cn}", leading to:
    String goldenContent = "cn: name\\ under";
    String responseAsString = new String(response.content.toByteArray());
    assertEquals(goldenContent, responseAsString);
  }

  @Test
  public void testGetDocContent_validButMissingDocId() throws Exception {
    final FakeAdaptor ldapAdaptor = new FakeAdaptor();
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntriesForOneServer();
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    // the above calls AdAdaptor.init() with the specified config.
    assertEquals(1, pusher.getRecords().size());
    String expectedDocId="server=0/cn=name\\ under,basedn";
    String expectedRecord="Record(docid=server=0/cn=name\\ under,cn=name\\ "
        + "under,basedn,delete=false,lastModified=null,resultLink=null,"
        + "crawlImmediately=false,crawlOnce=false,lock=false)";
    assertEquals(expectedRecord, pusher.getRecords().get(0).toString());
    pusher.reset();
    MockResponse response = new MockResponse();
    ldapAdaptor.getDocContent(new MockRequest(new DocId(expectedDocId + "xx")),
        response);
    assertTrue(response.notFound);
  }

  @Test
  public void testGetDocContentWhenFetchOneThrowsException() throws Exception {
    thrown.expect(IOException.class);
    final MockLdapContext ldapContext = new MockLdapContext();
    final LdapAdaptor ldapAdaptor = new LdapAdaptor() {
      @Override
      LdapServer newLdapServer(String host, String nick, Method method,
          int port, String principal, String passwd, String baseDN,
          String userFilter, String attributes, String globalNamespace,
          String localNamespace, int docsPerMinute, boolean disableTraversal,
          long ldapTimeoutInMillis, String displayTemplate) {

        return new LdapServer(host, nick, baseDN, userFilter, attributes,
            globalNamespace, localNamespace, docsPerMinute, disableTraversal,
            displayTemplate, ldapContext) {
          @Override
          void recreateLdapContext() {
            // leave ldapContext unchanged
          }
          @Override
          public LdapPerson fetchOne(String dn)
              throws InterruptedNamingException {
            throw new InterruptedNamingException("INE");
          }
        };
      }
    };
    AccumulatingDocIdPusher pusher = new AccumulatingDocIdPusher();
    Map<String, String> configEntries = defaultConfigEntriesForOneServer();
    pushGroupDefinitions(ldapAdaptor, configEntries, pusher, /*fullPush=*/ true,
        /*init=*/ true);
    // the above calls AdAdaptor.init() with the specified config.
    assertEquals(0, pusher.getRecords().size());
    String expectedDocId="server=0/cn=name\\ under,basedn";
    MockResponse response = new MockResponse();
    ldapAdaptor.getDocContent(new MockRequest(new DocId(expectedDocId)),
        response);
  }

  // tests for methods in the LdapAdaptor inner classes - starting with
  // AttributeValidationStatusSource

  @Test
  public void testAttributeValidationStatusSourceGetName() {
    LdapAdaptor.AttributeValidationStatusSource source
      = new LdapAdaptor.AttributeValidationStatusSource(null, null);
    assertEquals("Attribute Validation", source.getName(Locale.ENGLISH));
  }

  @Test
  public void testAttributeValidationStatusSourceRetrieveStatusNoServers() {
    List<LdapServer> servers = new ArrayList<LdapServer>();
    LdapAdaptor.AttributeValidationStatusSource source
        = new LdapAdaptor.AttributeValidationStatusSource(null, servers);
    LdapAdaptor.TranslationStatus expectedStatus
        = new LdapAdaptor.TranslationStatus(Status.Code.INACTIVE,
            LdapAdaptor.Translation.STATUS_ATTRIBUTE_VALIDATION_EMPTY);
    assertEquals(expectedStatus, source.retrieveStatus());
  }

  @Test
  public void testAttributeValidationStatusSourceRetrieveStatusSingleServer()
      throws Exception {
    final MockLdapContext ldapContext = new MockLdapContext();
    LdapServer single = LdapServerTest.makeMockLdapServer(ldapContext);
    List<LdapServer> servers = new ArrayList<LdapServer>();
    servers.add(single);
    LdapAdaptor.AttributeValidationStatusSource source
        = new LdapAdaptor.AttributeValidationStatusSource(null, servers);
    LdapAdaptor.TranslationStatus expectedStatus
        = new LdapAdaptor.TranslationStatus(Status.Code.UNAVAILABLE,
              LdapAdaptor.Translation.STATUS_ATTRIBUTE_VALIDATION_IN_PROGRESS,
              "nickname");
    assertEquals(expectedStatus, source.retrieveStatus());
  }

  @Test
  public void testAttributeValidationStatusSourceRetrieveStatusTwoServers()
      throws Exception {
    final MockLdapContext ldapContext = new MockLdapContext();
    final LdapServer first = new LdapServer("localhost", "first", "ou=basedn",
        "userFilter", "attr1,cn,dn" /* attributes */, "globalNamespace",
        "localNamespace", 1000 /* traversalRate */,
        false /* disableTraversal */, "" /* displayTemplate */, ldapContext) {
      @Override
      public LdapAdaptor.TranslationStatus getStatus() {
        return new LdapAdaptor.TranslationStatus(Status.Code.WARNING,
            LdapAdaptor.Translation.STATUS_ATTRIBUTE_VALIDATION_NOT_ALL_FOUND,
            "first", "missingAttribute");
      }
    };
    final LdapServer second = new LdapServer("localhost", "second", "ou=basedn",
        "userFilter", "attr1,cn,dn" /* attributes */, "globalNamespace",
        "localNamespace", 1000 /* traversalRate */,
        false /* disableTraversal */, "" /* displayTemplate */, ldapContext) {
      @Override
      public LdapAdaptor.TranslationStatus getStatus() {
        return new LdapAdaptor.TranslationStatus(Status.Code.ERROR,
            LdapAdaptor.
                Translation.STATUS_ATTRIBUTE_VALIDATION_USED_NOT_FETCHED,
            "second", "unfetchedAttribute");
      }
    };
    List<LdapServer> servers = new ArrayList<LdapServer>();
    servers.add(first);
    servers.add(second);
    LdapAdaptor.AttributeValidationStatusSource source
        = new LdapAdaptor.AttributeValidationStatusSource(null, servers);
    // expected status message combines both the above, with the greater (ERROR)
    // Code
    LdapAdaptor.TranslationStatus expectedStatus
        = new LdapAdaptor.TranslationStatus(Status.Code.ERROR);
    expectedStatus.setMessage("Server first: The following attribute(s) were "
        + "not found in any user: missingAttribute., Server second: The "
        + "following attribute(s) are specified in the display of users, but "
        + "are not fetched from LDAP: unfetchedAttribute.");
    assertEquals(expectedStatus, source.retrieveStatus());

    // get the same status code, even if the order of our servers is reversed.
    servers.clear();
    servers.add(second);
    servers.add(first);
    source = new LdapAdaptor.AttributeValidationStatusSource(null, servers);
    expectedStatus.setMessage("Server second: The following attribute(s) are "
        + "specified in the display of users, but are not fetched from LDAP: "
        + "unfetchedAttribute., Server first: The following attribute(s) were "
        + "not found in any user: missingAttribute.");
    assertEquals(expectedStatus.getCode(), source.retrieveStatus().getCode());
    assertEquals(expectedStatus.getMessage(Locale.ENGLISH),
        source.retrieveStatus().getMessage(Locale.ENGLISH));
    assertEquals(expectedStatus, source.retrieveStatus());
  }

  // next, the Translation inner class (only toString(...) needs testing)

  @Test
  public void testTranslatationToStringDefaultsToEnglish() {
    LdapAdaptor.Translation t
        = LdapAdaptor.Translation.STATUS_ATTRIBUTE_VALIDATION_ALL_FOUND;
    assertEquals("Server {0}: All Attributes OK.", t.toString());
    assertEquals("Server foo: All Attributes OK.", t.toString("foo"));
  }

  // next, the TranslationStatus inner class

  @Test
  public void testTranslatationStatusConstructorCanThrowNPE() {
    thrown.expect(NullPointerException.class);
    LdapAdaptor.TranslationStatus expectedStatus
        = new LdapAdaptor.TranslationStatus(null);
  }

  @Test
  public void testTranslatationStatusGetMessageCanReturnNull() {
    LdapAdaptor.TranslationStatus expectedStatus
        = new LdapAdaptor.TranslationStatus(Status.Code.ERROR);
    assertNull(expectedStatus.getMessage(Locale.ENGLISH));
  }

  @Test
  public void testTranslatationStatusEquals() {
    LdapAdaptor.TranslationStatus ts1
        = new LdapAdaptor.TranslationStatus(Status.Code.ERROR);
    LdapAdaptor.TranslationStatus ts2
        = new LdapAdaptor.TranslationStatus(Status.Code.NORMAL);
    LdapAdaptor.TranslationStatus ts3
        = new LdapAdaptor.TranslationStatus(Status.Code.ERROR);
    assertTrue(ts1.equals(ts3));
    ts3.setMessage("foo");
    assertFalse(ts1.equals(ts3));
    assertFalse(ts1.equals(ts2));
    assertFalse(ts1.equals(new Integer(42)));
  }

  @Test
  public void testTranslatationStatusHashcode() {
    LdapAdaptor.TranslationStatus ts1
        = new LdapAdaptor.TranslationStatus(Status.Code.ERROR);
    LdapAdaptor.TranslationStatus ts2
        = new LdapAdaptor.TranslationStatus(Status.Code.NORMAL);
    LdapAdaptor.TranslationStatus ts3
        = new LdapAdaptor.TranslationStatus(Status.Code.ERROR);
    assertEquals(ts1.hashCode(), ts3.hashCode());
    ts3.setMessage("foo");
    assertFalse(ts1.hashCode() == ts3.hashCode());
    assertFalse(ts1.hashCode() == ts2.hashCode());
  }

  // helper methods and classes below this line - no more test cases

  private MockLdapContext defaultMockLdapContext() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    ldapContext.addSearchResult("cn=name\\ under,basedn", "userFilter", "attr1",
        "val1");
    ldapContext.addSearchResult("cn=name\\ under,basedn", "userFilter", "cn",
        "name\\ under");
    ldapContext.addSearchResult("cn=name\\ under,basedn", "userFilter", "dn",
        "cn=name\\ under,basedn");
    return ldapContext;
  }

  // used by several tests above to share configuration specification.
  private Map<String, String> defaultConfigEntries() {
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ldap.servers", "server1,server2");
    configEntries.put("ldap.servers.server1.host", "localhost");
    configEntries.put("ldap.servers.server1.port", "1234");
    configEntries.put("ldap.servers.server1.ldapBindingDistinguishedName",
        "user-override");
    configEntries.put("ldap.servers.server1.ldapBindingPassword", "password");
    configEntries.put("ldap.servers.server1.connectionMethod", "ssl");
    configEntries.put("ldap.servers.server1.ldapSearchBase", "TBD");
    configEntries.put("ldap.servers.server1.userFilter", "TBD");
    configEntries.put("ldap.servers.server1.attributes", "dn,cn,attr1");
    configEntries.put("ldap.servers.server1.globalNamespace", "TBD");
    configEntries.put("ldap.servers.server1.localNamespace", "TBD");
    configEntries.put("ldap.servers.server1.docsPerMinute", "1000");
    configEntries.put("ldap.servers.server1.displayTemplate", "cn: {cn}");
    configEntries.put("ldap.servers.server2.host", "localhost");
    configEntries.put("ldap.servers.server2.port", "1234");
    configEntries.put("ldap.servers.server2.ldapBindingDistinguishedName",
        "user-override");
    configEntries.put("ldap.servers.server2.ldapBindingPassword", "password");
    configEntries.put("ldap.servers.server2.password", "password-override");
    configEntries.put("ldap.servers.server2.connectionMethod", "standard");
    configEntries.put("ldap.servers.server2.ldapSearchBase", "TBD");
    configEntries.put("ldap.servers.server2.userFilter", "TBD");
    configEntries.put("ldap.servers.server2.attributes", "dn,cn,attr1");
    configEntries.put("ldap.servers.server2.globalNamespace", "TBD");
    configEntries.put("ldap.servers.server2.localNamespace", "TBD");
    configEntries.put("ldap.readTimeoutSecs", "");
    configEntries.put("server.port", "5680");
    configEntries.put("server.dashboardPort", "5681");
    return configEntries;
  }

  // used by several tests above to share configuration specification.
  private Map<String, String> defaultConfigEntriesForOneServer() {
    Map<String, String> configEntries = new HashMap<String, String>();
    configEntries.put("gsa.hostname", "localhost");
    configEntries.put("ldap.servers", "server0");
    configEntries.put("ldap.servers.server0.host", "localhost");
    configEntries.put("ldap.servers.server0.port", "1234");
    configEntries.put("ldap.servers.server0.ldapBindingDistinguishedName",
        "user-override");
    configEntries.put("ldap.servers.server0.ldapBindingPassword", "password");
    configEntries.put("ldap.servers.server0.connectionMethod", "ssl");
    configEntries.put("ldap.servers.server0.ldapSearchBase",
        "cn=name\\ under,basedn");
    configEntries.put("ldap.servers.server0.userFilter", "userFilter");
    configEntries.put("ldap.servers.server0.attributes", "dn,cn,attr1");
    configEntries.put("ldap.servers.server0.globalNamespace", "TBD");
    configEntries.put("ldap.servers.server0.localNamespace", "TBD");
    configEntries.put("ldap.servers.server0.docsPerMinute", "1000");
    configEntries.put("ldap.servers.server0.displayTemplate", "cn: {cn}");
    configEntries.put("ldap.readTimeoutSecs", "");
    configEntries.put("server.port", "5680");
    configEntries.put("server.dashboardPort", "5681");
    return configEntries;
  }

  /**
   * Copied in from TestHelper (from the library)
   */
  // TODO(myk): Investigate pushing these methods back to the library
  // version.
  public static void initializeAdaptorConfig(Adaptor adaptor,
      Map<String, String> configEntries) throws Exception {
    final Config config = new Config();
    adaptor.initConfig(config);
    for (Map.Entry<String, String> entry : configEntries.entrySet()) {
      TestHelper.setConfigValue(config, entry.getKey(), entry.getValue());
    }
    adaptor.init(TestHelper.createConfigAdaptorContext(config));
  }

  public static void pushGroupDefinitions(LdapAdaptor adaptor,
      Map<String, String> configEntries, final DocIdPusher pusher,
      boolean fullPush, boolean init) throws Exception {
    if (init) {
      initializeAdaptorConfig(adaptor, configEntries);
    }
    if (fullPush) {
      adaptor.getDocIds(pusher);
    } else {
      // adaptor.getModifiedDocIds(pusher);
      throw new IllegalArgumentException("Incremental Push not implemented");
    }
  }

  /** A version of LdapAdaptor that uses only mock LdapServers */
  private class FakeAdaptor extends LdapAdaptor {
    @Override
    LdapServer newLdapServer(String host, String nick, Method method, int port,
        String principal, String passwd, String baseDN, String userFilter,
        String attributes, String globalNamespace, String localNamespace,
        int docsPerMinute, boolean disableTraversal, long ldapTimeoutInMillis,
        String displayTemplate) {

      MockLdapContext ldapContext = null;
      try {
        ldapContext = defaultMockLdapContext();
      } catch (Exception e) {
        fail("Could not create LdapContext:" + e);
      }
      return new LdapServer(host, nick, baseDN, userFilter, attributes,
          globalNamespace, localNamespace, docsPerMinute, disableTraversal,
          displayTemplate, ldapContext) {
        @Override
        void recreateLdapContext() {
          // leave ldapContext unchanged
        }
      };
    }
  };

  /** A trivial implemenation of {@link Request} */
  private class MockRequest implements Request {
    private final DocId docid;
    private final Date lastAccess;

    MockRequest(DocId docid) {
      this(docid, null);
    }

    MockRequest(DocId docid, Date lastAccess) {
      this.docid = docid;
      this.lastAccess = lastAccess;
    }

    @Override
    public boolean hasChangedSinceLastAccess(Date lastModified) {
      return lastModified.after(lastAccess);
    }

    @Override
    public Date getLastAccessTime() {
      return lastAccess;
    }

    @Override
    public DocId getDocId() {
      return docid;
    }
  }

  /**
   * An implementation of {@link Response} that implements only those items that
   * the adaptor uses.
   */
  private class MockResponse implements Response {

    boolean notModified = false;
    boolean notFound = false;
    String contentType;
    URI displayUrl;
    Map<String, String> metadata = new HashMap<String, String>();
    ByteArrayOutputStream content = new ByteArrayOutputStream();

    @Override
    public void respondNotModified() throws IOException {
      notModified = true;
    }

    @Override
    public void respondNotFound() throws IOException {
      notFound = true;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
      return content;
    }

    @Override
    public void setContentType(String contentType) {
      this.contentType = contentType;
    }

    @Override
    public void setLastModified(Date lastModified) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void addMetadata(String key, String value) {
      metadata.put(key, value);
    }

    @Override
    public void setAcl(Acl acl) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void putNamedResource(String fragment, Acl acl) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setDisplayUrl(URI displayUrl) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setSecure(boolean secure) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void addAnchor(URI uri, String text) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setNoIndex(boolean noIndex) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setNoFollow(boolean noFollow) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setNoArchive(boolean noArchive) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setCrawlOnce(boolean crawlOnce) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void setLock(boolean lock) {
      throw new UnsupportedOperationException();
    }
  }
}
