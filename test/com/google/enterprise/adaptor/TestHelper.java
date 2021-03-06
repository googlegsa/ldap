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

package com.google.enterprise.adaptor;

/**
 * Utility methods for tests.
 *
 * <p>This code lives in adaptor package instead of adaptor.ldap package
 * to work around visibility of <code>Config</code> class.
 * <p>It also replaces the TestHelper class from the library (by taking the
 * same package and class names.
 */
// TODO(jlacey): Remove this when the v4.1.4 library is available. See
// https://github.com/googlegsa/activedirectory/commit/d5d409d
public class TestHelper {
  // Prevent instantiation
  private TestHelper() {}

  public static void setConfigValue(Config config, String key, String value) {
    config.setValue(key, value);
  }

  private static final SensitiveValueDecoder SENSITIVE_VALUE_DECODER
      = new SensitiveValueDecoder() {
    @Override
    public String decodeValue(String notEncodedDuringTesting) {
      return notEncodedDuringTesting;
    }
  };

  public static AdaptorContext createConfigAdaptorContext(final Config config) {
    return new WrapperAdaptor.WrapperAdaptorContext(null) {
      @Override
      public Config getConfig() {
        return config;
      }

      @Override
      public void setPollingIncrementalLister(PollingIncrementalLister lister) {
        // do nothing
      }

      @Override
      public void addStatusSource(StatusSource source) {
        // do nothing
      }

      @Override
      public SensitiveValueDecoder getSensitiveValueDecoder() {
        return SENSITIVE_VALUE_DECODER;
      }

      @Override
      public void setAuthzAuthority(AuthzAuthority authzAuthority) {
        // do nothing
      }
    };
  }
}
