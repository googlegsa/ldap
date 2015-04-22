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

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchResult;

/** Representation of a single user retrieved from an LDAP Server. */
class LdapPerson {
  /** Stripped-down version of <code>AdEntity</code>. */
  private static final Logger log =
      Logger.getLogger(LdapPerson.class.getName());

  private String dn;
  private SearchResult searchResult;

  /**
   * Standard constructor for LdapPerson. The instance is created from LDAP
   * search result.
   * @param searchResult searchResult to create the object from
   */
  public LdapPerson(SearchResult searchResult) {
    if (searchResult == null) {
      throw new NullPointerException("searchResult can not be null");
    }
    dn = searchResult.getNameInNamespace();
    this.searchResult = searchResult;
  }

  /**
   * return a single attribute's value (or <code>null</code> if not found).
   */
  private Object getAttribute(Attributes attributes, String name)
      throws NamingException {
    Attribute attribute = attributes.get(name);
    if (attribute != null) {
      return attribute.get(0);
    } else {
      return null;
    }
  }

  /**
   * Returns commonName for the given user/group while making LDAP search query
   * to get all parents groups for a given group we need to retrieve the DN
   * name for a group.
   * @return group DN from group name.
   */
  public String getCommonName() {
    // LDAP queries return escaped commas to avoid ambiguity, find first not
    // escaped comma
    int comma = dn.indexOf(",");
    while (comma > 0 && dn.charAt(comma - 1) == '\\') {
      comma = dn.indexOf(",", comma + 1);
    }
    String tmpGroupName = dn.substring(0, comma > 0 ? comma : dn.length());
    tmpGroupName = tmpGroupName.substring(tmpGroupName.indexOf('=') + 1);
    tmpGroupName = tmpGroupName.replace("\\", "");
    return tmpGroupName;
  }

  public String getDn() {
    return dn;
  }

  @Override
  public String toString() {
    SBS result = new SBS();
    result.append("dn", dn);
    Attributes allAttrs = searchResult.getAttributes();
    NamingEnumeration<String> idEnumeration = allAttrs.getIDs();
    while (true) {
      try {
        if (!idEnumeration.hasMore()) {
          idEnumeration.close();
          return result.toString();
        }
      } catch (NamingException ne) {
        log.log(Level.WARNING, "Unexpected NamingException while processing "
            + "attributes from " + dn, ne);
        return result.toString();
      }
      // reaching here implies idEnumeration.hasMore() returned true, without
      // catching an exception.
      try {
        String id = idEnumeration.next();
        result.append(id, "" + getAttribute(allAttrs, id));
      } catch (NamingException ne) {
        log.log(Level.WARNING, "Unexpected NamingException while retrieving "
            + "attributes from " + dn, ne);
      }
    }
  }

  /**
   * @return all metadata for the current object.
   */
  public Map<String, String> asMetadata() {
    HashMap<String, String> result = new HashMap<String, String>();
    Attributes allAttrs = searchResult.getAttributes();
    NamingEnumeration<String> idEnumeration = allAttrs.getIDs();
    while (true) {
      try {
        if (!idEnumeration.hasMore()) {
          idEnumeration.close();
          return result;
        }
      } catch (NamingException ne) {
        // if calling hasMore() throws this exception, don't bother calling
        // .close() on idEnumeration.
        log.log(Level.WARNING, "Unexpected NamingException while processing "
            + "metadata from " + dn, ne);
        return result;
      }
      // reaching here implies idEnumeration.hasMore() returned true, without
      // catching an exception.
      try {
        String id = idEnumeration.next();
        result.put(id, "" + getAttribute(allAttrs, id));
      } catch (NamingException ne) {
        log.log(Level.WARNING, "Unexpected NamingException while retrieving "
            + "metadata from " + dn, ne);
      }
    }
  }

  public String asDoc(String displayTemplate) {
    Attributes allAttrs = searchResult.getAttributes();
    StringBuilder results = new StringBuilder();
    for (int i = 0; i < displayTemplate.length(); i++) {
      if (displayTemplate.charAt(i) == '{') {
        int closeBrace = displayTemplate.indexOf('}', i);
        if (closeBrace < 0) {
          throw new AssertionError("invalid display template: "
              + displayTemplate + ".  No close brace matches open at character "
              + i);
        } else {
          String attributeName = displayTemplate.substring(i + 1, closeBrace);
          Object value = null;
          try {
            value = getAttribute(allAttrs, attributeName);
          } catch (NamingException e) {
            // ignore the exception, and leave value as null -- results will
            // reflect this lack of value.
          }
          if (null == value) {
            log.finest("For DN " + getDn() + ", no value found for attribute "
                + attributeName);
            // leave results untouched.
          } else {
            results.append("" + value);
          }
          i = closeBrace; // skip ahead to just after variable specification
        }
      } else {
        results.append(displayTemplate.charAt(i));
      }
    }
    // escape everything, but then unescape (only) instances of "<br>"
    return escapeHTML(results.toString()).replaceAll("&#60;br&#62;", "<br>");
  }

  /**
   * @return a template that includes every attribute we (try to) fetch.
   */
  public static String allAttributesDisplayTemplate(String attributes) {
    StringBuilder results = new StringBuilder();
    for (String attribute : attributes.split(",")) {
      attribute = attribute.trim();
      results.append(attribute + ": " + "{" + attribute + "}<br>");
    }
    return results.toString();
  }

  private static String escapeHTML(String s) {
    StringBuilder out = new StringBuilder(Math.max(16, s.length()));
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      //TODO(myk): check if we need to escape ' and " as well.
      if (c > 127 || c == '<' || c == '>' || c == '&') {
        out.append("&#");
        out.append((int) c);
        out.append(';');
      } else {
        out.append(c);
      }
    }
    return out.toString();
  }

  /**
   * Used by the toString() method, to avoid repeated code
   */
  private static class SBS {
    private StringBuilder wrap = new StringBuilder();
    SBS append(String name, Object value) {
      wrap.append(name);
      wrap.append(" = " + value + ",");
      return this;
    }
    public String toString() {
      // eliminate trailing comma
      wrap.setLength(wrap.length() - 1);
      return wrap.toString();
    }
  }
}
