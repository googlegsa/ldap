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

import com.google.common.collect.Sets;

import com.google.enterprise.adaptor.StartupException;
import com.google.enterprise.adaptor.Status;
import com.google.enterprise.adaptor.ldap.LdapAdaptor.TranslationStatus;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.*;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;

/** Test cases for {@link LdapServer}. */
public class LdapServerTest {
  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testMockServer() throws Exception {
    LdapServer ldapServer = makeMockLdapServer(new MockLdapContext());
    assertEquals("localhost", ldapServer.getHostName());
  }

  @Test
  public void testMockServerInitialize() throws Exception {
    LdapServer ldapServer = makeMockLdapServer(new MockLdapContext());
    assertEquals("localhost", ldapServer.getHostName());
    ldapServer.initialize();
    assertEquals("[localhost] ", ldapServer.toString());
    assertEquals("dn={dn}, cn={cn}", ldapServer.getDisplayTemplate());
  }

  @Test
  public void testNPEOnNullConnectMethod() throws Exception {
    thrown.expect(NullPointerException.class);
    LdapServer ldapServer = new LdapServer("localhost", "nickname",
        null /* connectMethod */, 389, "principal", "password", "ou=basedn",
        "userFilter", "cn,dn" /* attributes */, 1000 /* traversalRate */,
        9000 /*ldapTimeoutInMillis */, "dn={dn}, cn={cn}");
  }

  @Test
  public void testNPEOnNullHostName() throws Exception {
    thrown.expect(NullPointerException.class);
    LdapServer ldapServer = new LdapServer(null, "nickname",
        Method.STANDARD /* connectMethod */, 389, "principal", "password",
        "ou=basedn", "userFilter", "cn,dn" /* attributes */,
        1000 /* traversalRate */, 9000 /*ldapTimeoutInMillis */,
        "dn={dn}, cn={cn}");
  }

  @Test
  public void testIAEOnEmptyHostName() throws Exception {
    thrown.expect(IllegalArgumentException.class);
    LdapServer ldapServer = new LdapServer("", "nickname",
        Method.STANDARD /* connectMethod */, 389, "principal", "password",
        "ou=basedn", "userFilter", "cn,dn" /* attributes */,
        1000 /* traversalRate */, 9000 /*ldapTimeoutInMillis */,
        "dn={dn}, cn={cn}");
  }

  @Test
  public void testNPEOnNullPrincipal() throws Exception {
    thrown.expect(NullPointerException.class);
    LdapServer ldapServer = new LdapServer("hostname", "nickname",
        Method.STANDARD /* connectMethod */, 389, null, "password",
        "ou=basedn", "userFilter", "cn,dn" /* attributes */,
        1000 /* traversalRate */, 9000 /*ldapTimeoutInMillis */,
        "dn={dn}, cn={cn}");
  }

  @Test
  public void testIAEOnEmptyPrincipal() throws Exception {
    thrown.expect(IllegalArgumentException.class);
    LdapServer ldapServer = new LdapServer("hostname", "nickname",
        Method.STANDARD /* connectMethod */, 389, "", "password",
        "ou=basedn", "userFilter", "cn,dn" /* attributes */,
        1000 /* traversalRate */, 9000 /*ldapTimeoutInMillis */,
        "dn={dn}, cn={cn}");
  }

  @Test
  public void testNPEOnNullPassword() throws Exception {
    thrown.expect(NullPointerException.class);
    LdapServer ldapServer = new LdapServer("hostname", "nickname",
        Method.STANDARD /* connectMethod */, 389, "principal", null,
        "ou=basedn", "userFilter", "cn,dn" /* attributes */,
        1000 /* traversalRate */, 9000 /*ldapTimeoutInMillis */,
        "dn={dn}, cn={cn}");
  }

  @Test
  public void testIAEOnEmptyPassword() throws Exception {
    thrown.expect(IllegalArgumentException.class);
    LdapServer ldapServer = new LdapServer("hostname", "nickname",
        Method.STANDARD /* connectMethod */, 389, "principal", "",
        "ou=basedn", "userFilter", "cn,dn" /* attributes */,
        1000 /* traversalRate */, 9000 /*ldapTimeoutInMillis */,
        "dn={dn}, cn={cn}");
  }

  @Test
  public void testREOnParametersOKButNoLdapServer() throws Exception {
    thrown.expect(RuntimeException.class);
    LdapServer ldapServer = new LdapServer("hostname", "nickname",
        Method.STANDARD /* connectMethod */, 389, "principal", "password",
        "ou=basedn", "userFilter", "cn,dn" /* attributes */,
        1000 /* traversalRate */, 9000 /*ldapTimeoutInMillis */,
        "dn={dn}, cn={cn}");
  }

  @Test
  public void testREOnParametersOKButNoLdapServer_SSL() throws Exception {
    thrown.expect(RuntimeException.class);
    LdapServer ldapServer = new LdapServer("hostname", "nickname",
        Method.SSL /* connectMethod */, 636, "principal", "password",
        "ou=basedn", "userFilter", "cn,dn" /* attributes */,
        1000 /* traversalRate */, 9000 /*ldapTimeoutInMillis */,
        "dn={dn}, cn={cn}");
  }

  @Test
  public void testRegularSearch() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    ldapContext.addSearchResult("basedn", "dn=empty", "attr1", "val1");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);

    Set<LdapPerson> resultSet = ldapServer.search("basedn", "dn=empty",
        new String[] { "attr1" }, true);
    assertEquals(1, resultSet.size());
    for (LdapPerson lp : resultSet) {
      assertEquals("dn = cn=name\\ under,basedn,attr1 = val1",
          lp.toString());
    }
  }

  @Test
  public void testSearchOnDnAndEmptyAttributes() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    ldapContext.addSearchResult("basedn", "dn=empty", "attr1", "val1");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);

    Set<LdapPerson> resultSet = ldapServer.search("basedn", "dn=empty",
        new String[] { "attr1", "dn", "" }, true);
    assertEquals(1, resultSet.size());
    for (LdapPerson lp : resultSet) {
      assertEquals("dn = cn=name\\ under,basedn,attr1 = val1",
          lp.toString());
    }
  }

  @Test
  public void testSearchOnDnAlone() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    ldapContext.addSearchResult("basedn", "dn=empty", "attr1", "val1");
    ldapContext.addSearchResult("basedn", "dn=empty", "dn", "dn=fakeDN");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);

    Set<LdapPerson> resultSet = ldapServer.search("basedn", "dn=empty",
        new String[] { "dn", }, true);
    assertEquals(1, resultSet.size());
    for (LdapPerson lp : resultSet) {
      assertEquals("dn = cn=name\\ under,basedn,dn = dn=fakeDN",
          lp.toString());
    }
  }

  @Test
  public void testSearchWithSlashInName() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    ldapContext.addSearchResult("dc=Either/Or", "filter", "attr1", "val1");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);

    Set<LdapPerson> resultSet = ldapServer.search("dc=Either/Or", "filter",
        new String[] { "attr1" }, true);
    assertEquals(1, resultSet.size());
    for (LdapPerson lp : resultSet) {
      assertEquals("dn = cn=name\\ under,dc=Either/Or,attr1 = val1",
          lp.toString());
    }
  }

  /*
   * Expected behavior: LdapServer searches for an LdapPerson;
   * LdapContext throws a NamingException;
   * LdapServer recovers and returns an empty Set of (no) LdapPerson instances.
   */
  @Test
  public void testSearchThrowsNamingException() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public NamingEnumeration<SearchResult> search(Name base, String filter,
        SearchControls searchControls) throws NamingException {
        if (!("dn=empty".equals(filter))) {
          return super.search(base, filter, searchControls);
        }
        throw new NamingException("Gotcha");
      }
    };
    ldapContext.addSearchResult("basedn", "dn=empty", "attr1", "val1");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);
    HashSet<LdapPerson> expected = new HashSet<LdapPerson>();
    assertEquals(expected,
        ldapServer.search("basedn", "dn=empty", new String[] { "attr1" },
        true));
  }

  /*
   * Expected behavior: LdapServer searches for an LdapPerson;
   * LdapContext returns a null Object (as the only member of the result set).
   * LdapServer recovers and returns an empty Set of (no) LdapPerson instances.
   */
  @Test
  public void testSearchReturnsNullObject() throws Exception {
    final Vector<SearchResult> resultVector = new Vector<SearchResult>();
    resultVector.add(new SearchResult("name", null, null));
    final MockLdapContext.SearchResultsNamingEnumeration badResults =
        new MockLdapContext.SearchResultsNamingEnumeration(resultVector);
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public NamingEnumeration<SearchResult> search(Name base, String filter,
          SearchControls searchControls) throws NamingException {
        return badResults;
      }
    };
    ldapContext.addSearchResult("basedn", "dn=empty", "attr1", "val1");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);
    HashSet<LdapPerson> expected = new HashSet<LdapPerson>();
    assertEquals(expected,
        ldapServer.search("basedn", "dn=empty", new String[] { "attr1" },
        true));
  }

  /*
   * Expected behavior: LdapServer (on call to initialize) calls getAttributes()
   * on ldapContext, which throws a NamingException.  LdapServer in turn throws
   * a RuntimeException.
   */
  @Test
  public void testConnectThrowsNamingException() throws Exception {
    thrown.expect(RuntimeException.class);
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public Attributes getAttributes(String name) throws NamingException {
        throw new NamingException("Can't connect");
      }
    };
    ldapContext.addSearchResult("basedn", "dn=empty", "attr1", "val1");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);
    ldapServer.initialize();
  }

  /*
   * Expected behavior: LdapServer (on call to initialize) calls getAttributes()
   * on ldapContext, which throws a CommunicationException (only on the first
   * call).  Subsequent calls to getAttributes() [namely, the one in the "catch"
   * logic of ensureConnectionIsCurrent()] are successful, and thus the call to
   * initialize() does not fail with an exception.
   */
  @Test
  public void testEnsureConnectionOnetimeException() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext() {
      boolean firstTime = true;
      @Override
      public Attributes getAttributes(String name) throws NamingException {
        if (firstTime) {
          firstTime = false;
          throw new CommunicationException("testing");
        } else {
          return super.getAttributes(name);
        }
      }
    };
    LdapServer ldapServer = new LdapServer("localhost", "nickname",
        "ou=basedn", "userFilter", "cn,dn" /* attributes */,
        1000 /* traversalRate */, "dn={dn}, cn={cn}", ldapContext) {
      @Override
      void recreateLdapContext() {
        // do nothing
      }
    };
    ldapServer.initialize();
  }

  /*
   * Expected behavior: LdapServer (on call to initialize) calls getAttributes()
   * on ldapContext, which throws a NamingException indicating that the read
   * timed out.  Conform (on the Cobertura coverage output) that the code to
   * handle this message gets executed.
   */
  @Test
  public void testEnsureConnectionTimesOut() throws Exception {
    thrown.expect(RuntimeException.class);
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public Attributes getAttributes(String name) throws NamingException {
        throw new NamingException("read timed out");
      }
    };
    LdapServer ldapServer = makeMockLdapServer(ldapContext);
    ldapServer.initialize();
  }

  /*
   * Expected behavior: Same behavior as above, only with an empty
   * NamingException.
   */
  @Test
  public void testEnsureConnectionThrowsEmptyNamingException()
      throws Exception {
    thrown.expect(RuntimeException.class);
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public Attributes getAttributes(String name) throws NamingException {
        throw new NamingException();
      }
    };
    LdapServer ldapServer = makeMockLdapServer(ldapContext);
    ldapServer.initialize();
  }

  /*
   * Expected behavior: LdapServer (on call to initialize) calls getAttributes()
   * on ldapContext, which throws a CommunicationException.  Subsequent call to
   * recreateLdapContext() throws a StartupException (which gets wrapped in the
   * NamingException that ensureConnectionIsCurrent throws), which then gets
   * wrapped into a RuntimeException by initialize().  Verify that the exception
   * can be unwrapped correctly.
   */
  @Test
  public void testEnsureConnectionWrapsStartupException() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public Attributes getAttributes(String name) throws NamingException {
        throw new CommunicationException("testing");
      }
    };
    LdapServer ldapServer = new LdapServer("localhost", "nickname",
        "ou=basedn", "userFilter", "cn,dn" /* attributes */,
        1000 /* traversalRate */, "dn={dn}, cn={cn}", ldapContext) {
      @Override
      void recreateLdapContext() {
        throw new StartupException("persistent problem");
      }
    };
    try {
      ldapServer.initialize();
    } catch (RuntimeException re) {
      assertTrue(re.getCause() instanceof NamingException);
      NamingException ne = (NamingException) re.getCause();
      assertTrue(ne.getMessage().contains("recreateLdapContext"));
      assertTrue(ne.getRootCause() instanceof StartupException);
    }
  }

  @Test
  public void testLdapServerBehaviorWhenLdapContextSetControlsThrowsException()
      throws Exception {
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public void setRequestControls(Control[] requestControls)
          throws NamingException {
        controls = requestControls;
        throw new NamingException("testing exception path");
      }
    };
    // populate additional attributes with values we can test
    final String filter = "ou=Users";
    final String userDn = "DN_for_default_naming_context";
    ldapContext.addSearchResult(userDn, filter, "cn", "user1")
               .addSearchResult(userDn, filter, "primaryGroupId", "users");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);
    ldapServer.initialize();
    Set<LdapPerson> resultSet = ldapServer.search(userDn, filter,
        new String[] { "cn", }, false);
    assertEquals(1, resultSet.size());
  }

  // compare to testRegularSearch() several pages above
  @Test
  public void testGetResponseControlsNullDoesNotThrowNPE() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext() {
      @Override
      public Control[] getResponseControls() throws NamingException {
        return null;
      };
    };

    ldapContext.addSearchResult("basedn", "dn=empty", "attr1", "val1");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);

    Set<LdapPerson> resultSet = ldapServer.search("basedn", "dn=empty",
        new String[] { "attr1" }, true);
    assertEquals(1, resultSet.size());
    for (LdapPerson lp : resultSet) {
      assertEquals("dn = cn=name\\ under,basedn,attr1 = val1",
          lp.toString());
    }
  }

  @Test
  public void testScanAllUnavailable() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    LdapServer ldapServer = makeMockLdapServer(ldapContext);
    TranslationStatus expectedStatus =
        new TranslationStatus(Status.Code.UNAVAILABLE);
    expectedStatus.setMessage("Server nickname: Attribute Validation still in"
        + " progress.");
    assertEquals(expectedStatus.getCode(), ldapServer.getStatus().getCode());
    assertEquals(expectedStatus.getMessage(Locale.ENGLISH),
        ldapServer.getStatus().getMessage(Locale.ENGLISH));
    assertEquals(expectedStatus, ldapServer.getStatus());
  }

  @Test
  public void testScanAllNormal() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    ldapContext.addSearchResult("ou=basedn", "userFilter", "attr1", "val1");
    ldapContext.addSearchResult("ou=basedn", "userFilter", "cn", "user1");
    ldapContext.addSearchResult("ou=basedn", "userFilter", "dn",
        "cn=user1,ou=basedn");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);

    Set<LdapPerson> resultSet = ldapServer.scanAll();
    assertEquals(1, resultSet.size());
    for (LdapPerson lp : resultSet) {
      assertEquals("dn = cn=name\\ under,ou=basedn,dn = cn=user1,ou=basedn,"
          + "attr1 = val1,cn = user1", lp.toString());
    }
    TranslationStatus expectedStatus =
        new TranslationStatus(Status.Code.NORMAL);
    expectedStatus.setMessage("Server nickname: All Attributes OK.");
    assertEquals(expectedStatus.getCode(), ldapServer.getStatus().getCode());
    assertEquals(expectedStatus.getMessage(Locale.ENGLISH),
        ldapServer.getStatus().getMessage(Locale.ENGLISH));
    assertEquals(expectedStatus, ldapServer.getStatus());
  }

  @Test
  public void testScanAllMissingAttributes() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    ldapContext.addSearchResult("ou=basedn", "userFilter", "cn", "user1");
    LdapServer ldapServer = new LdapServer("localhost", "nickname", "ou=basedn",
        "userFilter", "attr1,attr2,cn,dn" /* attributes */,
        1000 /* traversalRate */, "displayTemplateNotUsingAnyVariables",
        ldapContext);

    Set<LdapPerson> resultSet = ldapServer.scanAll();
    assertEquals(1, resultSet.size());
    for (LdapPerson lp : resultSet) {
      assertEquals("dn = cn=name\\ under,ou=basedn,cn = user1", lp.toString());
    }
    TranslationStatus expectedStatus =
        new TranslationStatus(Status.Code.WARNING);
    expectedStatus.setMessage("Server nickname: The following attribute(s) were"
        + " not found in any user: attr1, attr2.");
    assertEquals(expectedStatus.getCode(), ldapServer.getStatus().getCode());
    assertEquals(expectedStatus.getMessage(Locale.ENGLISH),
        ldapServer.getStatus().getMessage(Locale.ENGLISH));
    assertEquals(expectedStatus, ldapServer.getStatus());
  }

  @Test
  public void testScanAllUsingUnfetchedAttribute() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    ldapContext.addSearchResult("ou=basedn", "userFilter", "cn", "user1");
    ldapContext.addSearchResult("ou=basedn", "userFilter", "dn",
        "cn=user1,ou=basedn");
    LdapServer ldapServer = makeMockLdapServer(ldapContext, "attr2={attr2}");
    assertEquals("attr2={attr2}", ldapServer.getDisplayTemplate());

    Set<LdapPerson> resultSet = ldapServer.scanAll();
    assertEquals(1, resultSet.size());
    for (LdapPerson lp : resultSet) {
      assertEquals("dn = cn=name\\ under,ou=basedn,dn = cn=user1,ou=basedn,"
          + "cn = user1", lp.toString());
    }
    TranslationStatus expectedStatus =
        new TranslationStatus(Status.Code.ERROR);
    expectedStatus.setMessage("Server nickname: The following attribute(s) are "
        + "specified in the display of users, but are not fetched from LDAP: "
        + "attr2.");
    assertEquals(expectedStatus.getCode(), ldapServer.getStatus().getCode());
    assertEquals(expectedStatus.getMessage(Locale.ENGLISH),
        ldapServer.getStatus().getMessage(Locale.ENGLISH));
    assertEquals(expectedStatus, ldapServer.getStatus());
  }

  @Test
  public void testFetchOneNormal() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    ldapContext.addSearchResult("ou=basedn", "userFilter", "attr1", "val1");
    ldapContext.addSearchResult("ou=basedn", "userFilter", "cn", "user1");
    ldapContext.addSearchResult("ou=basedn", "userFilter", "dn",
        "cn=user1,ou=basedn");
    ldapContext.addSearchResult("basedn", "dn=empty", "attr1", "val1");
    LdapServer ldapServer = makeMockLdapServer(ldapContext);

    LdapPerson fetched = ldapServer.fetchOne("ou=basedn");
    assertEquals("dn = cn=name\\ under,ou=basedn,dn = cn=user1,ou=basedn,"
        + "attr1 = val1,cn = user1", fetched.toString());
  }

  @Test
  public void testFetchOneNoResults() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    LdapServer ldapServer = makeMockLdapServer(ldapContext);

    LdapPerson fetched = ldapServer.fetchOne("ou=basedn");
    assertNull(fetched);
  }

  @Test
  public void testFetchOneMoreThanOneResult() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    LdapServer ldapServer = new LdapServer("localhost", "nickname", "ou=basedn",
        "userFilter", "attr1,cn,dn" /* attributes */,
        1000 /* traversalRate */, "dn={dn}, cn={cn}", ldapContext) {
      @Override
      protected Set<LdapPerson> search(String baseDN, String filter,
          String[] attributes, boolean validateAttributes)
          throws InterruptedNamingException {
        SearchResult sr1 = new SearchResult("user 1", "user 1",
            new BasicAttributes());
        sr1.getAttributes().put("cn", "user1");
        sr1.setNameInNamespace("cn=user1");
        LdapPerson user1 = new LdapPerson(sr1);
        SearchResult sr2 = new SearchResult("user 2", "user 2",
            new BasicAttributes());
        sr2.getAttributes().put("cn", "user2");
        sr2.setNameInNamespace("cn=user2");
        LdapPerson user2 = new LdapPerson(sr2);
        return Sets.newHashSet(user1, user2);
      }
    };

    thrown.expect(IllegalArgumentException.class);
    thrown.expectMessage("More than one person found at ou=basedn");
    LdapPerson fetched = ldapServer.fetchOne("ou=basedn");
  }

  @Test
  public void testFetchOneNullLdapPersonResult() throws Exception {
    MockLdapContext ldapContext = new MockLdapContext();
    LdapServer ldapServer = new LdapServer("localhost", "nickname", "ou=basedn",
        "userFilter", "attr1,cn,dn" /* attributes */,
        1000 /* traversalRate */, "dn={dn}, cn={cn}", ldapContext) {
      @Override
      protected Set<LdapPerson> search(String baseDN, String filter,
          String[] attributes, boolean validateAttributes)
          throws InterruptedNamingException {
        return Sets.newHashSet((LdapPerson) null);
      }
    };

    thrown.expect(NullPointerException.class);
    thrown.expectMessage("Null LdapPerson found at ou=basedn");
    LdapPerson fetched = ldapServer.fetchOne("ou=basedn");
  }

  public static LdapServer makeMockLdapServer(LdapContext ldapContext) {
    return makeMockLdapServer(ldapContext, "dn={dn}, cn={cn}");
  }

  public static LdapServer makeMockLdapServer(LdapContext ldapContext,
      String displayTemplate) {
    return new LdapServer("localhost", "nickname", "ou=basedn", "userFilter",
        "attr1,cn,dn" /* attributes */, 1000 /* traversalRate */,
        displayTemplate, ldapContext);
  }
}
