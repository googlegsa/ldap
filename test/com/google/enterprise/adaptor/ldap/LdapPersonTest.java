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

import org.junit.Test;

import java.util.*;

import javax.naming.NamingException;
import javax.naming.directory.*;

/** Test cases for {@link LdapPerson}. */
public class LdapPersonTest {

  @Test
  public void testStandardConstructor() throws Exception {
    Attributes attrs = new BasicAttributes();
    attrs.put("cn", "user");
    attrs.put("givenName", "Test");
    attrs.put("sn", "User");

    SearchResult sr = new SearchResult("SR name", attrs, attrs);
    sr.setNameInNamespace("cn=user,ou=Users,dc=example,dc=com");
    LdapPerson ldapPerson = new LdapPerson(sr);
    assertEquals("user", ldapPerson.getCommonName());
    assertEquals("cn=user,ou=Users,dc=example,dc=com", ldapPerson.getDn());
    assertEquals("dn = cn=user,ou=Users,dc=example,dc=com,givenName = Test,"
        + "sn = User,cn = user", ldapPerson.toString());
  }

  @Test
  public void testConstructorWithEscapedComma() throws Exception {
    Attributes attrs = new BasicAttributes();
    attrs.put("cn", "name\\,with\\,commas");
    attrs.put("givenName", "Test");
    attrs.put("sn", "User");

    SearchResult sr = new SearchResult("SR name", attrs, attrs);
    sr.setNameInNamespace("cn=name\\,with\\,commas,ou=Users,dc=example,dc=com");
    LdapPerson ldapPerson = new LdapPerson(sr);
    assertEquals("name,with,commas", ldapPerson.getCommonName());
    assertEquals("cn=name\\,with\\,commas,ou=Users,dc=example,dc=com",
        ldapPerson.getDn());
    assertEquals("dn = cn=name\\,with\\,commas,ou=Users,dc=example,dc=com,"
        + "givenName = Test,sn = User,cn = name\\,with\\,commas",
        ldapPerson.toString());
  }

  @Test
  public void testConstructorWithNoCommaInDN() throws Exception {
    Attributes attrs = new BasicAttributes();
    attrs.put("cn", "com");
    attrs.put("givenName", "Test");
    attrs.put("sn", "User");

    SearchResult sr = new SearchResult("SR name", attrs, attrs);
    sr.setNameInNamespace("dc=com");
    LdapPerson ldapPerson = new LdapPerson(sr);
    assertEquals("com", ldapPerson.getCommonName());
    assertEquals("dc=com", ldapPerson.getDn());
    assertEquals("dn = dc=com,givenName = Test,sn = User,cn = com",
        ldapPerson.toString());
  }

  @Test
  public void testConstructorTrailingComma() throws Exception {
    Attributes attrs = new BasicAttributes();
    attrs.put("cn", "com");
    attrs.put("givenName", "Test");
    attrs.put("sn", "User");

    SearchResult sr = new SearchResult("SR name", attrs, attrs);
    sr.setNameInNamespace("dc=com,");
    LdapPerson ldapPerson = new LdapPerson(sr);
    assertEquals("com", ldapPerson.getCommonName());
    assertEquals("dc=com,", ldapPerson.getDn());
    assertEquals("dn = dc=com,,givenName = Test,sn = User,cn = com",
        ldapPerson.toString());
  }

  @Test
  public void testConstructorNullSearchResult() throws Exception {
    try {
      LdapPerson ldapPerson = new LdapPerson(null);
      fail("Should not have been able to construct a null-SR LdapPerson!");
    } catch (NullPointerException npe) {
      assertTrue(npe.getMessage() != null && npe.getMessage().contains(
          "can not be null"));
    }
  }

  @Test
  public void testAsDoc() throws Exception {
    Attributes attrs = new BasicAttributes();
    attrs.put("cn", "user");
    attrs.put("givenName", "Test");
    attrs.put("sn", "User");
    attrs.put("name", null);

    SearchResult sr = new SearchResult("SR name", attrs, attrs);
    sr.setNameInNamespace("cn=user,ou=Users,dc=example,dc=com");
    LdapPerson ldapPerson = new LdapPerson(sr);
    assertEquals("user", ldapPerson.getCommonName());
    assertEquals("cn=user,ou=Users,dc=example,dc=com", ldapPerson.getDn());
    assertEquals("dn = cn=user,ou=Users,dc=example,dc=com,name = null,"
        + "givenName = Test,sn = User,cn = user", ldapPerson.toString());
    assertEquals("Name: Test User", ldapPerson.asDoc("Name: {givenName} {sn}"));
    assertEquals("Name: ", ldapPerson.asDoc("Name: {name}"));
    assertEquals("cn: user<br>givenName: Test<br>sn: User<br>",
        ldapPerson.asDoc(ldapPerson.allAttributesDisplayTemplate(
            "cn,givenName,sn")));
    assertEquals("", ldapPerson.asDoc("{missing}"));
    try {
      String unexpectedResult = ldapPerson.asDoc("{missing");
      fail("Did not catch expected AssertionError");
    } catch (AssertionError e) {
      assertEquals("invalid display template: {missing.  No close brace matches"
          + " open at character 0", e.getMessage());
    }
    // test escapeHTML method
    assertEquals("&#60;\"&#38;'&#146;&#62;", ldapPerson.asDoc("<\"&'\222>"));
    // test that <br> is unescaped
    assertEquals("a<br>b", ldapPerson.asDoc("a<br>b"));
  }

  @Test
  public void testNamingException() throws Exception {
    final BasicAttribute attr = new BasicAttribute("exception") {
        @Override
        public Object get(int ix) throws NamingException {
          throw new NamingException("expectedException");
        }
    };

    final Attributes attrs = new BasicAttributes() {
      @Override
      public Attribute get(String attrID) {
        if ("exception".equals(attrID)) {
          return attr;
        } else {
          return super.get(attrID);
        }
      } };
    attrs.put("cn", "user");
    attrs.put("givenName", "Test");
    attrs.put("sn", "User");
    attrs.put("exception", attr);

    SearchResult sr = new SearchResult("SR name", attrs, attrs);
    sr.setNameInNamespace("cn=user,ou=Users,dc=example,dc=com");
    LdapPerson ldapPerson = new LdapPerson(sr);
    assertEquals("user", ldapPerson.getCommonName());
    assertEquals("cn=user,ou=Users,dc=example,dc=com", ldapPerson.getDn());
    assertEquals("dn = cn=user,ou=Users,dc=example,dc=com,givenName = Test,"
        + "NamingException = javax.naming.NamingException: expectedException",
        ldapPerson.toString());
    assertEquals("Name: ", ldapPerson.asDoc("Name: {exception}"));
  }

}
