// Copyright 2026 Google LLC
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
//
////////////////////////////////////////////////////////////////////////////////

package com.google.crypto.tink.integration.gcpkms;

import static com.google.common.truth.Truth.assertThat;
import static com.google.crypto.tink.integration.gcpkms.internal.GcpKmsUtil.mlDsaPublicKeyPem;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertThrows;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.cloud.kms.v1.ChecksummedData;
import com.google.cloud.kms.v1.CryptoKeyVersion;
import com.google.cloud.kms.v1.GetPublicKeyRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.KeyManagementServiceGrpc.KeyManagementServiceImplBase;
import com.google.cloud.kms.v1.KeyManagementServiceSettings;
import com.google.cloud.kms.v1.ProtectionLevel;
import com.google.cloud.kms.v1.PublicKey;
import com.google.common.hash.Hashing;
import com.google.crypto.tink.PublicKeyVerify;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Base64;
import org.conscrypt.Conscrypt;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.runner.RunWith;

@RunWith(Theories.class)
public final class GcpKmsPublicKeyVerifyTest {
  private static final String KEY_NAME_WRONG_FORMAT =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions";
  private static final String KEY_NAME_ECDSA_P256 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/1";
  private static final String KEY_NAME_ECDSA_P384 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/2";
  private static final String KEY_NAME_RSA_PKCS1_2048_SHA256 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/3";
  private static final String KEY_NAME_RSA_PKCS1_4096_SHA256 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/4";
  private static final String KEY_NAME_RSA_PKCS1_4096_SHA512 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/5";
  private static final String KEY_NAME_RSA_PSS_2048_SHA256 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/6";
  private static final String KEY_NAME_RSA_PSS_4096_SHA256 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/7";
  private static final String KEY_NAME_RSA_PSS_4096_SHA512 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/8";
  private static final String KEY_NAME_GET_PUBLIC_KEY_EXCEPTION =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/9";
  private static final String KEY_NAME_PUBLIC_KEY_CHECKSUM_MISMATCH =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/10";
  private static final String KEY_NAME_KEY_NAME_MISMATCH =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/11";
  private static final String KEY_NAME_UNSUPPORTED_ALGORITHM =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/12";
  private static final String KEY_NAME_RSA_PKCS1_3072_SHA256 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/13";
  private static final String KEY_NAME_RSA_PSS_3072_SHA256 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/14";
  private static final String KEY_NAME_ML_DSA_44 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/15";
  private static final String KEY_NAME_ML_DSA_65 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/16";
  private static final String KEY_NAME_ML_DSA_87 =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/17";
  private static final String KEY_NAME_SLH_DSA_128S =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/18";
  private static final String KEY_NAME_HASH_SLH_DSA =
      "projects/cloudkms-test/locations/global/keyRings/KR/cryptoKeys/K1/cryptoKeyVersions/19";

  private static final byte[] signData = "data".getBytes(UTF_8);

  // Public keys and signatures below are similar to the tink-cc-gcpkms verify tests, to keep
  // the Java and C++ implementations consistent. All signatures are over the message "data".

  // $ openssl ecparam -name prime256v1 -genkey -noout -out ecdsa-private.pem
  // $ openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem
  private static final String ECDSA_P256_PUBLIC_KEY =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPu+j4MR6Veo9F2YyKq0AObMM3UoN\n"
          + "K4Z6V0tej/9smL+QfqkILtkY0DROmBbLb/tOg+zi/q6CAG5FuBK7CaZP0g==\n"
          + "-----END PUBLIC KEY-----\n";
  // $ echo -n "data" | openssl dgst -sha256 -sign ecdsa-private.pem | base64
  private static final String ECDSA_P256_SIGNATURE =
      "MEUCIQD1n5HhsGwZ4hU2LVqTnUqQLlGidxPVVUBPbg8W1FGm4QIgQtSebi2H9/EZPKSsqYnkIFts"
          + "zI4jNZYWfcOFOjtJi7o=";

  // $ openssl ecparam -name secp384r1 -genkey -noout -out ecdsa-private.pem
  // $ openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem
  private static final String ECDSA_P384_PUBLIC_KEY =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEvhSzPPgaNlVa7ALdPv2TU/y7zcztJKMW\n"
          + "Uyb4EFljhW+HwMedJ9rq58P9vCO81GK+uzMElfKXwyh9Hwki3OrHw/U/QpEHrYAc\n"
          + "mjodwJBbZu8a/6Oc2bXN96IwqOhAM70l\n"
          + "-----END PUBLIC KEY-----\n";
  // $ echo -n "data" | openssl dgst -sha384 -sign ecdsa-private.pem | base64
  private static final String ECDSA_P384_SIGNATURE =
      "MGUCMEJreAXQPgGuVKNEctuQRAh8sbdWbnxwbOIERx6A7KrXfx/VIGYsEIX9OjIgNGc+pwIxAOVN"
          + "n7DccgsZjhOwaL+HsI0RqbBFxRIaLQjlO9JT5BWxbsRX/7nio7krXpcfXFhnDg==";

  // $ openssl genrsa -out rsa-private.pem 2048
  // $ openssl rsa -in rsa-private.pem -pubout > rsa-public.pem
  private static final String RSA_2048_PUBLIC_KEY =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnWdm/pltnPoPL7V+vQzI\n"
          + "YO0xm4d9lTBdWHWyvWIwFbG9ePPI2DS5bAUREY8pW/L7FzhHGvgrkuLgIFP8WTYd\n"
          + "4fm1L+QhhSIIltdnW8IeZobRsmrnz8oN/U6VPN8wGgPUzv1MM/vWQcNfDvv5E/kw\n"
          + "sJAD1e+V6S2rts2f8zFHHP71vXITSumOaVvJTVHZgyWEXA63C2MEQVMhzXrsnJua\n"
          + "5JY9TDAhFHDRiKzng9ZSbRmItutY8+FdlmoZVjWnFnhdloVvn/KzSjv0FmmHwmAI\n"
          + "Tt1aTrN7iWBoy/YBL61yxMMr91gtWh5Dp6KXYErYxS6v5fh5VOmrYJCeMugyokIW\n"
          + "zQIDAQAB\n"
          + "-----END PUBLIC KEY-----\n";

  // $ openssl genrsa -out rsa-private-3072.pem 3072
  // $ openssl rsa -in rsa-private-3072.pem -pubout > rsa-public-3072.pem
  private static final String RSA_3072_PUBLIC_KEY =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAi9Q2UorCOwp7Y5r+qO0n\n"
          + "mdlz8/GLQ1dh+9XR/wtL2uMGwEbTyziFt3UocxlxZLw6dQtHY3xfMW37lpRX5PFt\n"
          + "T68SeWRh+Cz+6i75NKa+FHrYM4d/HLYjFk+vOw75GIVfe0epi3UdMs5Ob8LGqaKP\n"
          + "PF6uPk/PSEJvXZ78Is2yODuUCecV0aDajQ/873jdwBrzXuaqG9SpLf8UTg891nuS\n"
          + "P+yZ075LvUu3ylcDxFsWclenATML3sgkrW1qQJKW5/UXRUQGNNnBPqF2EgIUlc6E\n"
          + "N8RszNjWKtzbs4EKirHd881Naw656nM/KfLj+00g0Vfd3/lvi2o8YFbDKcnKYZfI\n"
          + "tdohx9Zt4b3slCZOF/zMlvPKCn9tpa17A7rCBv57I80/+evKaq5PX84G+UcfV5kz\n"
          + "LHi+FNXBtJLzYr8JKxkad4U2ecjrK1jjvJtuPbqYosKCpRfBGsy3CdfeYn2xTtDZ\n"
          + "s+l73QYpWpnXUyjydhsTafQY0dce6azjrvmRWGFoSSRHAgMBAAE=\n"
          + "-----END PUBLIC KEY-----\n";

  // $ openssl genrsa -out rsa-private-4096.pem 4096
  // $ openssl rsa -in rsa-private-4096.pem -pubout > rsa-public-4096.pem
  private static final String RSA_4096_PUBLIC_KEY =
      "-----BEGIN PUBLIC KEY-----\n"
          + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1GeEVEj1xv0ppPMAVMmK\n"
          + "PIsx7xt/6lyM2I9Am11HDVZ8+pN9FgGb7hMIXqBQWWhLCStvLBJPSlv+RUsw1GK4\n"
          + "3MD+Yxlc4X132KaC/Z6qIf+aD5FthfETtTEJem7HCTCSEyJXoeXYu69NrN9e+m+V\n"
          + "bcIVFaZ+f31tiDtSZi7fTCVbmSGG9WeqKZe/hKuhOan8lH2IJmxFjOk9hKFVqxB0\n"
          + "wTMFw7enAwLJxDqQMFXVK8zgjfvJ147AIol96VbS7si9Lnff9TfNjzcGfe1hsXNP\n"
          + "g10gLFu2N2LmjD9sb1gfWJGSGTsJiyX/owu+jj7GCWyQhY6hFTvZKbE0c1ZFLYbv\n"
          + "IiUBYJZUBk58iFgO7WA+fync9jDN9nNlw68e3xnqF7iherDS7IqZ5x8d+b+wgJKy\n"
          + "pBJI5hYY3OJB2yp4Ao9K4wQFxvJBBpg3jCGoofVVjrA8lePa3Yb8EHy+z5u5mYNj\n"
          + "VSxw8SXzqNsAgl5aW6c7Gs1c7m+Hpfdi4K+OJl60H0eYF+ks0KVShNRYri6q347D\n"
          + "IVpX3Qc6YOGPUHUj9lX7NfFJseGzbiJYTOQ+kVxvCmUqKMfq1vLvkgEfTpK53pTy\n"
          + "Z8h8oIZLTJo4MPwFbQAWNcKBGh43fMLWVWCED64N1S/2qNVv1R90OCerKLaX8WdY\n"
          + "txOSq3pgn5BD2tHhZ7ZmxTsCAwEAAQ==\n"
          + "-----END PUBLIC KEY-----\n";

  // $ echo -n "data" | openssl dgst -sha256 -binary | openssl pkeyutl -sign -inkey rsa-private.pem
  // \
  //     -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pkcs1 | base64
  private static final String RSA_PKCS1_2048_SHA256_SIGNATURE =
      "NI2jo+WIrKjoyIR/jtlSBT0BJJJ0aDgIi86rXVOqPq35DyULjT1JwtKvgtqocNaeeKDQ4HRQhNKn"
          + "ZYeDzQO6nHD6SgngAv0v9FBGTph4VUNZ0To1Bzlk8LP+P/0PWWy59aAHzAFULCiU7/6nP2KSInbR"
          + "vg7UmMRXcfw956D3skFZn2dbu/xCRhYuZCiej72s6sNVRC1dHpIBz2+/f7ux4/gJgiYJGC9bvmkR"
          + "DzZIy7e3zf1Be7ZT/zAreAbL+Zk8BEvoWItV0YkDUs33MkFY1MCR44grai6fGGOJAxgahlcgvkue"
          + "O3tnao5epghHnwamS9I2h8zcBe984Z0MR+NXfw==";

  // $ echo -n "data" | openssl dgst -sha256 -binary | openssl pkeyutl -sign \
  //     -inkey rsa-private-3072.pem -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pkcs1 | base64
  private static final String RSA_PKCS1_3072_SHA256_SIGNATURE =
      "iPyX74OCyZOh7GO7Y1UI3ucb8OMb9LoiIjHrW4jFKpS/aLjDGXrjEFbfsF3JITOFfOWx3M8+jIGs"
          + "4wwmHWiWCufqkbf4gtndGAoaEddeK2ph8tqXEnzkq8o5qDk175ffeZYmVI7/vi5xwc2oz5kd17wf"
          + "CD0MmFGxLef1C22Wz+MJTRi0LX6Ngsy/vR4Fx5N7+EXDdqPYx2ZLIhyQvXd7GztFxZTa8s7yQ6Gr"
          + "q2oslO13aMiu1dC9y9QYWLoY4uhF0te2WJerW5lRUp+00pk2ruC/yTaLXwS3bFZFx4FmNTClQCC/"
          + "JLugNekKJv9/FXex/L6muQseXxfezRiKV3fY2Ee7qxngZZZ/EU/TIDqBN3q3dE0eCyA/A2Ox7xtx"
          + "QqyTeIDeURZN9j5YtaVffp47oV2M0pSHTmcIyIwhHLx0MqWUPGUP3NvpjclNCeC5L8YieQKJiEBl"
          + "eoLpVA4nc2KEEdHyb+pFpaN+Pvw2V8X29uRl7ZIAkzxbnbaog7p3xza8";

  // $ echo -n "data" | openssl dgst -sha256 -binary | openssl pkeyutl -sign \
  //     -inkey rsa-private-4096.pem -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pkcs1 | base64
  private static final String RSA_PKCS1_4096_SHA256_SIGNATURE =
      "cqJsTB70moE9s+3OElRbmLFFXkRIYU0TKuhL+y8UMr/XUOqcXdrynnionthm6DJm681TJ88eHN29"
          + "eeZiyTt1UtQZBbMjAUOdrhcndHNdoxfQuVPJ8a4HuMOWXTT6B2ewxNDrWjhJZ2PARPBnl3OR1JWe"
          + "x8ynj7gIPFcsW6+pVDilMmxRkHHxj3xKplQ+uYRlY9ifggcs/ujx+UxZcScicfZWTbNuGlmddN6+"
          + "IV6q++gW7VoU+OZSaLBttFU93ohkLNnFYjRF1JxdKXNzOciJ7/AHtDd/XJ2zqnJsJCm0G/GkK+UB"
          + "W3lTkFcWjaqEqQEFKxVygIWIQsKF760BoZDkTgeSFeSo0aUAFG3WlKFoDQKQUVVgoKq0cU+VMqin"
          + "vfAunEHJAmq4An9IcxX3As8gyGByHO5xfoXwRrQfrJunRGWPvp5MXFm+i53FkfkDs1+DtypSKkX0"
          + "BrCSu1uRmIZxt0MhgJWgvQdXtglH3y4b7bmFOG/dvyGhMoSSpfRdjulPL/P5jW+zlDdwpr8WtrnY"
          + "RC0m4X8YpiBhXojYd1rtne5Q+A8t8EKNt2SXPadhSsRPoNF5wgD9tkoTvE0SbbdUm59c+cp9Hdj+"
          + "oJTWhYtpAcC+p6WebsZ9ILE180j44RRMF9GRk34AiDhr5bOwR+EEi8ScMj7LQhb+lcfQKwYr0EU=";

  // $ echo -n "data" | openssl dgst -sha512 -binary | openssl pkeyutl -sign \
  //     -inkey rsa-private-4096.pem -pkeyopt digest:sha512 -pkeyopt rsa_padding_mode:pkcs1 | base64
  private static final String RSA_PKCS1_4096_SHA512_SIGNATURE =
      "lq3wThF4Xa99ICz0vsTSBMa+uUclsECaUetUmLDvB/zjmHBIzeFrf6l0b/OtF9gnqq35nbvnJlaC"
          + "8vCZJMYfiGahkUfi7Vqw4sxxCfmBTbN+F8bl4n0dV+Na00pNHgRNKLaOcstyvBC74DD4e3mM799T"
          + "3nOELe8ASUCa0jGlVDhrSIQVt1wnfNZktrLWRjWm+cCz9w5RXira2fqz3/sDQbG6AcpJ8SzsfBd4"
          + "/52sQTRtrIDs2T+0BEku77rFozXMhO0ttkVsFijNsUr0R+FG3/gkPVBbMJl5ClCJw7qifsTsdw0M"
          + "iCunp6lvAm9CAz5AZMjA+iFgFSILaPLTFHy8Z5kFLcTqhgHcQAgqGGlhiucuuXruO+b907GyQ4tx"
          + "qWtWVuWmNWVgC9HAh3ra1tN7SgLj7cKFABq1GqNzkp6bDMtjutr8GfXMmIG/at4Uj9pmlpe+1ob1"
          + "dEFU8Oq/xdnrATTIzagqHrHqMSLqZ4/vXwwaDoIDDlR3tULV9/pPhh+60F4z8c4SbDSPOHTMxT3f"
          + "RtxO+ko9JZmka5PaGnjtNQVc16XYTR+23asReB6gcIu2xvvIhxtxASANdg5Nk+L/M6IZeFx0hnGO"
          + "B4AVQ2YF8IJ58A1rr9tT41MtyaPhGjOTNuFPlnyAJ5V/CalwuAtGFq5fMokC+AzcL4p9KruIodE=";

  // $ echo -n "data" | openssl dgst -sha256 -binary | openssl pkeyutl -sign -inkey rsa-private.pem
  // \
  //     -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:32 | base64
  private static final String RSA_PSS_2048_SHA256_SIGNATURE =
      "FhypcoCQT2X/9tn3qo7s9GSFjPew41hV2OveWlAwElYzke4dlfVIrpgnfpjOMHJuD2BIJc7ePKi2"
          + "XPTS+QS3LmWx8Qv4wKUgdluDK0ZD+Dm2MAHfYaLq3J3LqJhjOkcnM2KuYJcUFj40edYkhwg1oYUc"
          + "4EEKrSIh72Px6GGJa0nbRuCYx9vm7eH5zx/M4wIpOF+ScczoL6LkOyX8hFB2Ub9LxBh3OPahe/zT"
          + "QKy0+gMjUGqjwTxq3EBlkngY0LWh2fE+COhoq6mAddViyVfJjHCApY1KZXPWgg5tzbpttmDf6yKT"
          + "StTyAxt686GkeWL0kUzsmkGDQB1Ld6WJ+5KNlQ==";

  // $ echo -n "data" | openssl dgst -sha256 -binary | openssl pkeyutl -sign \
  //     -inkey rsa-private-3072.pem -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss \
  //     -pkeyopt rsa_pss_saltlen:32 | base64
  private static final String RSA_PSS_3072_SHA256_SIGNATURE =
      "aM6ZNE2qRKuxc2Mdehc3Uju9eE8U4C9687M2keVOiHEeDCUo1uJJmBOPYJI8MM1h2G+KCMdy0006"
          + "zNuLGhANYASmplSCJfiI6eEJRhAgcX2km9VGeIF07VH+X0ZrdxTKX9hq4RnQL+NiAnhcDjmYfNF1"
          + "F+W86JjXt1QhWVPwCt0EhxC0dC41WyvM8a7r5e6P6VymkplCUuMIbnwNU4HtYyuc3HJnOgEODnrw"
          + "Z8jlNuHEHM0v7LEzYTcUXtmC/IhLYloxqOPVechEy0TZYC3Ir3rxa8JduTPCPnrYLsWRRUAchYIh"
          + "5eS+f4KHWSvZ8zPdjt18VouLTKZMhNRB/RlgV3SH8Ic3OVCoy979piJDyu9DGCRVZ5VoLH4Vuhkd"
          + "F5InvIzt7Lq5ApkF1JlKVM1V328ParbgGu0H+klCown/mD9sruFzJIzCat9wbX9gOMJAVSaZ6ZCK"
          + "XeLIF+aVe8kOxayniAulOzbK1xatXChSQk6vtg1egFu4XkwhI7C9IWDG";

  // $ echo -n "data" | openssl dgst -sha256 -binary | openssl pkeyutl -sign \
  //     -inkey rsa-private-4096.pem -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss \
  //     -pkeyopt rsa_pss_saltlen:32 | base64
  private static final String RSA_PSS_4096_SHA256_SIGNATURE =
      "WMEq0q7+U24gx2SOwzWRI0M7aoYAvpQnz5kPMKRA4Ortn0bcJIsKXy4g4facoLygo+hJ4KiMmCQP"
          + "sbNoz/3hgfQcTc5XfPAVbkBkT3nnYcY77wib1f/VSQpdObcAs4bE7EyQrXUB4fkIdQlj96GvreP6"
          + "Vak0xjpSEdv0mA2rXuPWKsXUObsX1Wkto3Kz5DNplzxO2ofroo3VL8Lu3jv3OHH+c/fc9mKO5LRW"
          + "4nIaf6n8IkNq7zR2OioN3461+Uhc+5PpFBy9SCpdWJmlCYstN13Z8OLRi5zYhq8J8JBtJh1RkFDo"
          + "mNrEbkGKDd+VIgbuYpS7zRtJRFuBcHBrOorTLy84YWOW5xIn1HeWax/mPneUs+gJk4Eu7wGaFDyh"
          + "pJiLhw99AFn7b+Q2hCaQm+6/SW1YjBqKPX7Sd9JTjadsTO+t/3kEI31TN/2MTTAkTuRYswgm8dBs"
          + "RXmKMGJmzC7SIMxg0+tmuVkwbz2CPnv5CLSH9F6MuN1uynSWCzurOkyQUAy6J/A49EO/EPm+HY1W"
          + "F29Oz+3Hn++CDnBoB9fKorFWgqD0j6qwK6JDzT9e7Dn0Cp+EhbffU0BBYM0F6YgmbGN7Kf7XnrsY"
          + "ywVS6k6dmdkTzFWyRWszkfBNW3iTaOraGuEvQ8qi/93vNUFefGqDg0Mn7pm2bVL0Dukpc5RpRjg=";

  // $ echo -n "data" | openssl dgst -sha512 -binary | openssl pkeyutl -sign \
  //     -inkey rsa-private-4096.pem -pkeyopt digest:sha512 -pkeyopt rsa_padding_mode:pss \
  //     -pkeyopt rsa_pss_saltlen:64 | base64
  private static final String RSA_PSS_4096_SHA512_SIGNATURE =
      "zMztdsH/VYhGe32DCt3aSn9gUhzPREQhkMUi6bCHTzdV9wrN2yuAPCWRmBPymXh2tB7chB/gbJWU"
          + "YQeXYZtBgRnJKaPHhtQpeDFJwzbJt2eIiFA9RthLbo9kg1U9VuiXqfjKmkbj8Z5qbyJXVdl4f6hh"
          + "Ai2aGXaEpliRPLRUyuJRIIOU4O8clTQAoHqHCOLNtfpYU2LSABL6nM9awf/OGD98SFJ7sLwBDtB0"
          + "b7imZxBYayf0E1h1pza8XdHVYmTxQ+jdc5nYk+G27AzU0SZUviB5tdAt62xtFZiRi6vkk7FgfY+m"
          + "1jqv9FmklOiBuuZDPjdfQ1zlYTLdQHrGVCgO9jenC+OkeVyKOPmVgvETBsSEkr/W7kf2OM84mksy"
          + "mO10c0xqTCOi/cJd6zUYmi5IksU8DXQ1y8ZABzSoqIlRsOmyRQiW0CH+HmFl8HgtwZ9cSiKYtzag"
          + "I5QnFhvzpt3/fI52HeAebUFsd9x4xNmvcDkdXTO/cHCJXSRRO88LKBtuKZHgiXEfyQubEcTKMJxe"
          + "Q1sM0efzF/Br3aylzgzd+a5KvMq/0WGoVmHgvrH41lVxIlL2K1MHopfWz1Qi9sFVyB3MmIXIpcSL"
          + "GGYPgxL+zvqtZL+01ury1ASUw28414i4LU7OUO3C1oQc/tR4eETXYZ++qSsS6XmT7Br8k7h1VpQ=";

  // Generated the private key with Cloud KMS and exported public key.
  private static final String ML_DSA_44_PUBLIC_KEY =
      "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"
          + "+A==";

  // Generated with Cloud KMS through AsymmetricSign.
  private static final String ML_DSA_44_SIGNATURE =
      "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"
          + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0TIS8=";

  // Generated the private key with Cloud KMS and exported public key.
  private static final String ML_DSA_65_PUBLIC_KEY =
      "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"
          + "P6hfdtqZug4zT5/nX2w=";

  // Generated with Cloud KMS through AsymmetricSign.
  private static final String ML_DSA_65_SIGNATURE =
      "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"
          + "GSAn";

  // Generated the private key with Cloud KMS and exported public key.
  private static final String ML_DSA_87_PUBLIC_KEY =
      "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"
          + "TBjEccBnPjjoXQutOE77DbF+muWyajLvgjRX";

  // Generated with Cloud KMS through AsymmetricSign.
  private static final String ML_DSA_87_SIGNATURE =
      "/ds8s1tkNb2Zw7dngmchKwWT8e2entRKsEmiRa91eFYf9QKhdqhnVIVm8TIGhb7V+anuLj1kA2eo"
          + "6oKJ88nyIcxvH90rct4qxOjtFKkgyfxQSz5JsB3+SiRX55rL6A8Sa39NLhwLieDCx+doM7dmrikC"
          + "2cgYeBULx9QWdX75a76gq25W0xTAVrfw/GjMTFKWb6mrRdY6dzdcmk0kj1zFW1h4vSWcUV2GqfSy"
          + "2fn5ots4RQ58TafhM5zgevcAKl6Blyy/u7rHfbI2E9XOQjnq92Zx4QuV2YM00cdVM545KpRzv2Uy"
          + "h1xIq17+LmQypthHXbafRa1N2ajv4ovquYzZDIo/p8Tg4fkK5e8OzYIAUzPnzM2Px+WmnKX2a2c5"
          + "/rfs1KjiNxtCa80M36FfdTtDmk5Cb+5Qp+zt5hOkRhpwK1l/XKI0zldAEtA+8u0aeiDBhqbe+ewu"
          + "auEgArVMObsSikaU/xrrSR7dooJ1ITJNT8gYTgJV7Wvc9nQOagDIV34e6NZ1VkclYiC0RM5pPwT3"
          + "27rveUwIwBZT9OCCwm80XnJIb+ndeODA+qNhkmI+i/1DXqcDVBU7OAA8VCrj/glUlhv79nawv9+y"
          + "I/EGfC3hQW2PSFJjNz/Db46Wcfsx/N+RgM7qxNrhjIcuKiayp/9mV5fEwQcyO9Eb7n1xHwmOlHR0"
          + "X+uKSHrasWxuzSgcQIKCCX9BYaVj/oyL5PgBS0CjGTqAxNuOb+QRPUT0V/Ifp1BtzSPByvq+7I8c"
          + "f0HJ4Kr/Gy+8ak66vDYplSqrdvo2ADt/xd7i/W1458Uzz801rn3aheT0YfgdwqUAUBhdjYfgZ6SE"
          + "OVcdQn1K/H4uV/x0JyRInKC2PWlJ0CmiAQc9ZyB+yx8JtYgKzWjb+v7P73d8fZ/7J4LdTr1owq56"
          + "NMwChViFZuTK4ELSLxEaACl6GUvCJZnCl1RYHGxItom3CgSfbJmVhvLIs6l+S2hN6oTqAidyhPr0"
          + "J10Y75pUcAoNTYme0sBzakSsvrThqWkqprrwfRJQY0o2eHlFPug+aLEUKNniMZQ86odMZVU3YsDv"
          + "ia8JKDK4EC0x8hVMhzkfNNKWEimbO10BjBLj7vtShaTMXIOtiGH3Ztp+ZuvvnjW5siBjJjRtj3Wg"
          + "yrw55S4bQBDImhCFCTOFTYzoqaHM1FPHnaNf5zR6qkZQo6MUMDTlLzyW4UomiADwzAqdql6Sbhk0"
          + "0U0jHWCE6a6pgUP548gApeajRPISc3MzYzZ4acbNzfbuaqsUpZBQXm8ikybdWSzBqdhdXfLyn4X8"
          + "vRXK81VHbODmkiNs98NSMrtgFJK+hGkRrX14u8I5EOrCyuhYSKsS6fUCniYHee62gCnRr7IioNhf"
          + "tx/w4/lH7fWe4a+B//ugcSDex2Ms1jwmyubQRMbADxCMZh9+F2EwZggVP8i55B3ohQurdDbYf0Bj"
          + "bFYkqSxY1dP8KU5CtRe+gHLgP5deKPkoQ00N8f2/VErIc09+PzYme9pTLeDyzA6WiUNx6VRNQD9b"
          + "JHXeJJOUrIW1NH2uLzKqXly5UZtkKZ273DtqzVlBdG5gdYhFpe0uuHdHsVnXhuJ8kaRIPhfLIixC"
          + "mul18PLKDtm7ZXpKgxSGyg9QHZ+2hi/YXpP0uD7CtXo1Z1hlYdHxxSwB2jl5o0x+fbjidyfq1jv8"
          + "pCfDJnmLs8OqJ2cF60xVUP97rJPklj0tg/G8PzrK/S9WifyT3LlUSkgkJRb01cA8FPgThmxbowch"
          + "yWxHWqLuP7iEfZdol/E+SGl4/yvOLTW7szsgmTAc9TnF5VvYEbwSK2jmhrbNIrpXSd0xHUEhmq3O"
          + "BoAqMs1n9+7ejulKSdBeSJxet+YWTs+MPd+64um4BSMr/Brg79L/4S2axFDrendQ4952KtIjqvW9"
          + "E+M4fbu5dZ4bRDCLWnYDyd83nPvkulVCs13kJVUQf5XjtX9zFEWP6OZTEu9Cr0s6GBx9uSDPg6xA"
          + "fhzt5aOTmheGQN91rQYDHQn0N+z/ie4mqVFW2mcLYHnBDfK7LjDXAnKeIKhnyJJdRSB/XCkPZi/V"
          + "FfBEMTbRUZwNOJ85V9dR9d8aeSytFTjPl9Ke0jB7KYU6mR4JyuJ3ZZC1BV7thwkYeOsTFthPTvLC"
          + "K0VdMOvUAGBN08z/g3gAheO0XZPGLR03V4oDFIdMTxltvCGM3a47OKPzf1sFk5lawWLTzqQWKXCR"
          + "aM0bFx4EVvRt8bNoAhbyJ/y2cA+KZJnZQkkN0Lvx2bRYBoUwu4KXfKOR8bglyC8/gz0x6jKTPNOm"
          + "TcVW6wwmW+eDo5PdVp6585fYDmmE1zRJW8rD+uAXBPNkHGSmElGQgUgQNUZmAwVOUjuxqMY9ISGZ"
          + "1j5P1P4YR96qFXDqziwR1pf+lhv8a3/XpuTHe5xOCiG3Yp5EbsI+gHpFwkxF4238C9kWtngXaxV3"
          + "O8ky158yD/Uf45Ni60YLoonE37pxjHpf+Glq7Z6BQgbKjF99+j8mAlN3XIEIP1r+Un1TjKICFvnW"
          + "vLCrtC8RqprFGemE1w/m7sAj4I2XbKuhISbsVXZadlOM1m0iNqlV7kBB4Rf6vnlF8kzsjRRPLhgr"
          + "9sUx/ciutFfGIA0cQcdjhbi4rd/XDVLzGPODWXOtVYCEdMmhlpSDlHoAl7QM5bnwPQe87tzSrCb/"
          + "S2SSAUx3osOz5otA4F2ySrT2QT45ZTU7B9RJxgXg6wluNwSq4B/Za1iWzKlH9O3BSbE3Ll4b2k8c"
          + "2lL4hl6mzAP+cWr2xBid4oRGfcoEa7ufuIaYWNyO9qRfRGB/kdAwZDTdbs/r9TUayCRa7hw8GSB0"
          + "2PWyqUtMunF3GfQbbkB7i+qG846ZASKmzkNv0YCQ9BgkbXmxtgpuFzw9gsTmkeEVAoT39P0zWIWV"
          + "s6Eav3+TuksiksgkIhR750ue/SPJPtePTvsYZwrrsNSeqcHgs2G5m3k9PkiW7rBjPdtUnwErgZX3"
          + "ZxzQp1IGg4430zsmGQvHboZaSA1mY/vzYFdrEcBtq+NdLZhhC/M4xzsd6hQKrAJtOlwV4Org9xtM"
          + "GTKh/uORklOqPOPKg900Nj7e7axaFkoLuagknt7aH3S+WtLM+NlNDWZEYELrZgeDhjk6uagRj17s"
          + "VH7+S7c75PxBhk+yZb9fnoBlA8xu7vkc/Ey7UYu7vAN/noA5mi5Zt+lLRU2GL18KEb+h1TnZ1IAT"
          + "QirY4RfOjYdVe8/vQlagR2U2Jg+DOyDA/40jcU5JTW4WYZx3b3H0G71zHv4zg3RCn4Nh52rOSQn2"
          + "iGXBqdkGWW8ttUWjFRwkMCNP0r0V/JW5tJXrlrJ+eFao0jsmHbjzUhP4sS3JrJXkQbYLVIsgI1g7"
          + "SEWJjeuRkTrQN3Cv0vJCuZhmKIhuXUuEWuQSayJ4sBZa18uZu8fPpGS6U+P52VdcFm9K2FUIdKn9"
          + "yBb9JrMOC3WGjxR7FNNw5BkYJ4sskd1UHL1ac77fyjNK/2TzR7QZa5R49QozxXAjZn1hTMMcHPGm"
          + "qjY6pIs4yqhkj7I64+9eDMlxS0Px0fWZyZa7U913kqChMfzJkLXpJ9sDT+Mwm93cBvLaZHReYXlL"
          + "sGNbDK4RZhggvI4LwwyUoxo0obCqc8y8EKlGSVymeMTMvoDLL0Pb2mz1I5TlRvUWglY8jlhLWbMa"
          + "1QSqrth0OK+FyMoBL85UBM5bGPS9cePxzsTgEHk877IuILiPgkzQD6zFAGHlbbt/nPJ2bBxAirik"
          + "OaT8Fpd/HWWLlwnRPsUQsjQbnIKtkfmIB1fRq7JGFxaFdwVtlRoeV1P7KvS2YRqnzHCAMJYVv3VM"
          + "QN6iItX+DHDVi9qEdfJre2A0olH9an5uSnLW205sK37q782UMR6mOxIfBT2XhAXKfkcM8+0Ktwyi"
          + "33POpLR3LKpOu5+o5jCPe7PkEWSaGT+BuR1+5zMlQeIujgGIrgEkuUhu9O2uqvM4kQIqHv4CFdN7"
          + "iTty/Cdnbeg69UJV08dGRQhUiapNRLhIL0yG9yqJJ5bRMRrOyi3G6J7p0TqyKZWIAlAYxr7R0j1P"
          + "EEicn8TAW4tyE9C4VIjHbfoEziMOfarUisNBzF9dTGe4jv+Ys9otaA1ftKDqOT2RvMaMDP0rU05o"
          + "oxHSqQ/6AN3+U16QvDdWkEibIwVesUkUFT15xkNB93IERNtuIKiIhK8SIoi4TAzzCxzmTIy9qxxB"
          + "cjl1c9LIPVs65joS+ByRJtiDkNN7RWP6TfD2QLK7ZNKgv5VCS1AEG+dcFGHgAKawpUdMkAtbish9"
          + "Z252LqpDt0Iw5OBUVuOet7m2KzU3FGYC8glfVWbJep/fXVGLeZqA4FYOT9FWGEme9XbeWqwt99y4"
          + "DZnwL12Wnvp9+M6692yu7KrfZZu7+vKL2qWyzJYSTg9XwVaBTsKxhSM5PbFSokcjDF1iYD+GmvYR"
          + "E6dtcWTmEgyVAjhHL+bUhdA2+CCA2r8BHh5BqzAidOvxAQMUqcLDu/7guhUq2/RmRWwtjpEmRfgy"
          + "VQNTqcDgU52ZBW16cFyX5gqQfhcxFjRH8xdjLVtpF4G47lpS9hqLgMJQQ9iHx7X/bAIEIxIl5jEk"
          + "gaabL47CSkXslv2LX8rls5vJwoR9hBZ1glbelemabbCIckhgJx2wAMML/mhy9Tyk6E5Uf4v8fDzK"
          + "Z1sx8GGwSwZ3rS80IOLlTHfNsnOVavo2NS7Xu2vcpVeEZpBvuX8L64xV+VnQ++Kcqv0HIaCmFoqv"
          + "S5RP4aGzgJmSEz/gkdixyyRIsLbVTsovpOH4WW1D7k4FQYgjOYWOhpt8z8aqejdWzWCe1R3+BQLD"
          + "A4lXK2ZtwCu8eZ+csEoAHe9nzA0WM6fHy3dL4+YtprrKa410oUuszvPrWG9s8k0OoXxFFjtmTSop"
          + "U2+RItOSxzRksbALEovwe3bw5O0EQpZLGVELzKvNO3csQ75JRqQ+Cy391UQ+iskRYdeej17/JEY8"
          + "GqG3hf2q0jNldyOtQl8SOi8cdQqv3SLX7H3OTeB4QkVG+8JTVfrKROTcszxTsGeYnvu275Wq2P6Z"
          + "R+Ld+e78qGnwKQA92gz2niWWMmlOgFiQ8VII5JhR/Tf+3GqZDzPNRPeFTcrjqs6Gxf8ZLCMrMO69"
          + "7dUenNlv0To+bCurqOvPIkE/xkWPmEs8rtneC+IZOlAp07KVI1tXo+dpvr0/wE9pHwPHTfedeTmI"
          + "BE6cOWfILf7siqjjhLDHw3tjnNZaYckkWSMqTkBVJtyjwtmbjpOlv7JTTUd7/+jvb6fV044hOsgp"
          + "NdBEhq5El3Bi9f1MiBl/+/Tkpuevx7VSGSMfVLkm/T1hQBJ0Klr5VQ4D+xM4VEhGtCjUk7fQ1L2l"
          + "RdEMX4RgIkJiZnZr1oa6EeS9pQex5czG/vpKYntlUlYZqvbe8lcpBt0ppMIpd2NUNX5ppw4vkIcU"
          + "bGWqM3w/B2AxNb4pWdqw89GgXKow+IqThKCVFTNfUvwdzADi19na2BM9KPg3Fjwnyv/kVtkLAsWp"
          + "W9p0tC8V9AEjSNGXjSMDVHkRivXsjcYZNbaHTiYrxwpiSy+L7LbWnvur/aS8KrHqIIQSW03Tejhd"
          + "n/dHfFWEi8gj6DV+LrDy4tZvW7m/WBpMnXUCkgFMffOCPOIqQkNUq8L66QJtqwR7DB2GsDKOsfWd"
          + "excsl8sqJhzUV0SZjw2WwZ+/dMTYZwU5tOkr5nix+X5d2Z0UHyDeR4FYOLfN9AMOqzxPEUEQAwLy"
          + "qrTQzkxo+1Bbz4z6YolWfn4KL0KNHrmSow/CbcjC36NdEaPdnt/IJ5qiTMdghGYOAoc6m5osXuwt"
          + "Z9fsnWiX0cdB/jhsikGNuOQWzA640ALo5/J42QS6QstNzzhEh82fRs+f1cBpfR/pdQsYyt/hVXss"
          + "9SfGvYIUE/SLTQEBowGlImJDD+wbzsTu6TdiohKSxqb04UX1njCfxnF0gp5MsIecDnAwGj2awQDq"
          + "04h5QQiMTrDgi5QKxM8PfC7j9P/qBJVczO2h2mTvq82UlyrHG226Nf8MECJf5PjceybaiDGq2g/f"
          + "F/LYSAxnZzLvnpEO+fGV58l3JOW75sTyzgjgBbP+9PLqDrIG3C4L0PoTL2l1lpvS1+Dv8zk9R2ig"
          + "0kBcYpi0zv0BDxggNTdXYZPi6Bs/sdPa/1RYWmNwkbz1GT0/c3eKLEpPYuUAAAAAAAAAAAAAAAAA"
          + "AAALERgjKTE3PA==";

  // Generated the private key with Cloud KMS and exported public key.
  private static final String SLH_DSA_PUBLIC_KEY = "kdcOIrFCC5kN8S4i0+R+AoSc9gYIJ9jEQ6zG235ZmCQ=";

  // Generated with Cloud KMS through AsymmetricSign.
  private static final String SLH_DSA_SIGNATURE =
      "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";

  // DER SubjectPublicKeyInfo prefixes that precede the raw key bytes in an ML-DSA PEM (RFC 9881).
  private static final String ML_DSA_44_SPKI_PREAMBLE =
      "30820532300b06096086480165030403110382052100";
  private static final String ML_DSA_65_SPKI_PREAMBLE =
      "308207b2300b0609608648016503040312038207a100";
  private static final String ML_DSA_87_SPKI_PREAMBLE =
      "30820a32300b060960864801650304031303820a2100";

  /** This rule manages automatic graceful shutdown for the registered servers and channels. */
  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  private KeyManagementServiceClient kmsClient;

  // Implements a fake KeyManagementService that only serves GetPublicKey: verification is local and
  // never calls AsymmetricSign.
  private static final class FakeKmsImpl extends KeyManagementServiceImplBase {
    @Override
    public void getPublicKey(
        GetPublicKeyRequest request, StreamObserver<PublicKey> responseObserver) {
      String name = request.getName();
      if (name.equals(KEY_NAME_GET_PUBLIC_KEY_EXCEPTION)) {
        responseObserver.onError(
            Status.PERMISSION_DENIED.withDescription("Permission denied.").asRuntimeException());
        return;
      }

      ByteString data;
      CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm;
      switch (name) {
        case KEY_NAME_ECDSA_P384:
          data = ByteString.copyFromUtf8(ECDSA_P384_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384;
          break;
        case KEY_NAME_RSA_PKCS1_2048_SHA256:
          data = ByteString.copyFromUtf8(RSA_2048_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256;
          break;
        case KEY_NAME_RSA_PKCS1_3072_SHA256:
          data = ByteString.copyFromUtf8(RSA_3072_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256;
          break;
        case KEY_NAME_RSA_PKCS1_4096_SHA256:
          data = ByteString.copyFromUtf8(RSA_4096_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256;
          break;
        case KEY_NAME_RSA_PKCS1_4096_SHA512:
          data = ByteString.copyFromUtf8(RSA_4096_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512;
          break;
        case KEY_NAME_RSA_PSS_2048_SHA256:
          data = ByteString.copyFromUtf8(RSA_2048_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_2048_SHA256;
          break;
        case KEY_NAME_RSA_PSS_3072_SHA256:
          data = ByteString.copyFromUtf8(RSA_3072_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_3072_SHA256;
          break;
        case KEY_NAME_RSA_PSS_4096_SHA256:
          data = ByteString.copyFromUtf8(RSA_4096_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA256;
          break;
        case KEY_NAME_RSA_PSS_4096_SHA512:
          data = ByteString.copyFromUtf8(RSA_4096_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA512;
          break;
        case KEY_NAME_ML_DSA_44:
          data =
              mlDsaPublicKeyPem(
                  ML_DSA_44_SPKI_PREAMBLE,
                  ByteString.copyFrom(Base64.getDecoder().decode(ML_DSA_44_PUBLIC_KEY)));
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_44;
          break;
        case KEY_NAME_ML_DSA_65:
          data =
              mlDsaPublicKeyPem(
                  ML_DSA_65_SPKI_PREAMBLE,
                  ByteString.copyFrom(Base64.getDecoder().decode(ML_DSA_65_PUBLIC_KEY)));
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_65;
          break;
        case KEY_NAME_ML_DSA_87:
          data =
              mlDsaPublicKeyPem(
                  ML_DSA_87_SPKI_PREAMBLE,
                  ByteString.copyFrom(Base64.getDecoder().decode(ML_DSA_87_PUBLIC_KEY)));
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_ML_DSA_87;
          break;
        case KEY_NAME_SLH_DSA_128S:
          // Unlike ML-DSA, SLH-DSA and Pre-hash SLH-DSA keys are not available in PEM format, so
          // KMS rejects the initial PEM request; the library retries in NIST_PQC format.
          if (request.getPublicKeyFormat() != PublicKey.PublicKeyFormat.NIST_PQC) {
            responseObserver.onError(
                Status.INVALID_ARGUMENT
                    .withDescription("Only NIST_PQC format is supported")
                    .asRuntimeException());
            return;
          }
          data = ByteString.copyFrom(Base64.getDecoder().decode(SLH_DSA_PUBLIC_KEY));
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_SLH_DSA_SHA2_128S;
          break;
        case KEY_NAME_HASH_SLH_DSA:
          if (request.getPublicKeyFormat() != PublicKey.PublicKeyFormat.NIST_PQC) {
            responseObserver.onError(
                Status.INVALID_ARGUMENT
                    .withDescription("Only NIST_PQC format is supported")
                    .asRuntimeException());
            return;
          }
          data = ByteString.copyFrom(Base64.getDecoder().decode(SLH_DSA_PUBLIC_KEY));
          algorithm =
              CryptoKeyVersion.CryptoKeyVersionAlgorithm.PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256;
          break;
        case KEY_NAME_UNSUPPORTED_ALGORITHM:
          // The algorithm is rejected before the public key is parsed, so the PEM is never used.
          data = ByteString.copyFromUtf8(ECDSA_P256_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256;
          break;
        case KEY_NAME_ECDSA_P256:
        case KEY_NAME_PUBLIC_KEY_CHECKSUM_MISMATCH:
        case KEY_NAME_KEY_NAME_MISMATCH:
          data = ByteString.copyFromUtf8(ECDSA_P256_PUBLIC_KEY);
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256;
          break;
        default:
          responseObserver.onCompleted();
          return;
      }

      long crc32c = Hashing.crc32c().hashBytes(data.asReadOnlyByteBuffer()).padToLong();
      if (name.equals(KEY_NAME_PUBLIC_KEY_CHECKSUM_MISMATCH)) {
        // Corrupt the checksum so it no longer matches the public key.
        crc32c += 1;
      }
      // Return a different key name to simulate a KMS response with a mismatched key name.
      String responseName = name.equals(KEY_NAME_KEY_NAME_MISMATCH) ? KEY_NAME_ECDSA_P256 : name;

      PublicKey response =
          PublicKey.newBuilder()
              .setName(responseName)
              .setProtectionLevel(ProtectionLevel.SOFTWARE)
              .setAlgorithm(algorithm)
              .setPublicKey(
                  ChecksummedData.newBuilder()
                      .setData(data)
                      .setCrc32CChecksum(Int64Value.of(crc32c)))
              .build();
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    }
  }

  @Before
  public void setUp() throws Exception {
    // ML-DSA/SLH-DSA verification is delegated to Conscrypt, which must be installed as a JCA
    // provider.
    if (Conscrypt.isAvailable()) {
      Security.addProvider(Conscrypt.newProvider());
    }

    // Create a server, add service, start, and register for automatic graceful shutdown.
    String serverName = InProcessServerBuilder.generateName();
    grpcCleanup.register(
        InProcessServerBuilder.forName(serverName)
            .directExecutor()
            .addService(new FakeKmsImpl())
            .build()
            .start());

    // Create a client channel and register for automatic graceful shutdown.
    ManagedChannel channel =
        grpcCleanup.register(InProcessChannelBuilder.forName(serverName).directExecutor().build());
    KeyManagementServiceSettings kmsSettings =
        KeyManagementServiceSettings.newBuilder()
            .setCredentialsProvider(NoCredentialsProvider.create())
            .setTransportChannelProvider(
                FixedTransportChannelProvider.create(
                    GrpcTransportChannel.newBuilder().setManagedChannel(channel).build()))
            .build();
    kmsClient = KeyManagementServiceClient.create(kmsSettings);
  }

  private PublicKeyVerify newVerifier(String keyName) throws Exception {
    return GcpKmsPublicKeyVerify.builder()
        .setKeyName(keyName)
        .setKeyManagementServiceClient(kmsClient)
        .build();
  }

  private void assertVerifies(String keyName, String base64Signature) throws Exception {
    PublicKeyVerify verifier = newVerifier(keyName);
    byte[] signature = Base64.getDecoder().decode(base64Signature);
    // Throws GeneralSecurityException if verification fails.
    verifier.verify(signature, signData);
  }

  /** Returns whether the installed Conscrypt provider supports ML-DSA. */
  private static boolean mlDsaSupported() {
    Provider provider = Security.getProvider("Conscrypt");
    if (provider == null) {
      return false;
    }
    try {
      Signature unused = Signature.getInstance("ML-DSA-65", provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  /** Returns whether the installed Conscrypt provider supports SLH-DSA. */
  private static boolean slhDsaSupported() {
    Provider provider = Security.getProvider("Conscrypt");
    if (provider == null) {
      return false;
    }
    try {
      Signature unused = Signature.getInstance("SLH-DSA-SHA2-128S", provider);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  /** A signature algorithm together with its key name and test signature. */
  private static final class VerifyCase {
    final String keyName;
    final String signature;

    VerifyCase(String keyName, String signature) {
      this.keyName = keyName;
      this.signature = signature;
    }

    @Override
    public String toString() {
      return keyName;
    }
  }

  private static boolean isPqcAlgorithmSupported(VerifyCase verifyCase) {
    if (verifyCase.keyName.equals(KEY_NAME_SLH_DSA_128S)) {
      return slhDsaSupported();
    }
    return mlDsaSupported();
  }

  @DataPoints("classicalVerifyCases")
  public static final VerifyCase[] classicalVerifyCases =
      new VerifyCase[] {
        new VerifyCase(KEY_NAME_ECDSA_P256, ECDSA_P256_SIGNATURE),
        new VerifyCase(KEY_NAME_ECDSA_P384, ECDSA_P384_SIGNATURE),
        new VerifyCase(KEY_NAME_RSA_PKCS1_2048_SHA256, RSA_PKCS1_2048_SHA256_SIGNATURE),
        new VerifyCase(KEY_NAME_RSA_PKCS1_3072_SHA256, RSA_PKCS1_3072_SHA256_SIGNATURE),
        new VerifyCase(KEY_NAME_RSA_PKCS1_4096_SHA256, RSA_PKCS1_4096_SHA256_SIGNATURE),
        new VerifyCase(KEY_NAME_RSA_PKCS1_4096_SHA512, RSA_PKCS1_4096_SHA512_SIGNATURE),
        new VerifyCase(KEY_NAME_RSA_PSS_2048_SHA256, RSA_PSS_2048_SHA256_SIGNATURE),
        new VerifyCase(KEY_NAME_RSA_PSS_3072_SHA256, RSA_PSS_3072_SHA256_SIGNATURE),
        new VerifyCase(KEY_NAME_RSA_PSS_4096_SHA256, RSA_PSS_4096_SHA256_SIGNATURE),
        new VerifyCase(KEY_NAME_RSA_PSS_4096_SHA512, RSA_PSS_4096_SHA512_SIGNATURE),
      };

  @Theory
  public void verifyWorksForClassicalAlgorithm(
      @FromDataPoints("classicalVerifyCases") VerifyCase verifyCase) throws Exception {
    assertVerifies(verifyCase.keyName, verifyCase.signature);
  }

  @DataPoints("pqcVerifyCases")
  public static final VerifyCase[] pqcVerifyCases =
      new VerifyCase[] {
        new VerifyCase(KEY_NAME_ML_DSA_44, ML_DSA_44_SIGNATURE),
        new VerifyCase(KEY_NAME_ML_DSA_65, ML_DSA_65_SIGNATURE),
        new VerifyCase(KEY_NAME_ML_DSA_87, ML_DSA_87_SIGNATURE),
        new VerifyCase(KEY_NAME_SLH_DSA_128S, SLH_DSA_SIGNATURE),
      };

  @Theory
  public void verifyWorksForPqc(@FromDataPoints("pqcVerifyCases") VerifyCase verifyCase)
      throws Exception {
    if (!isPqcAlgorithmSupported(verifyCase)) {
      return;
    }
    assertVerifies(verifyCase.keyName, verifyCase.signature);
  }

  @Theory
  public void verifyFailsForInvalidPqcSignature(
      @FromDataPoints("pqcVerifyCases") VerifyCase verifyCase) throws Exception {
    if (!isPqcAlgorithmSupported(verifyCase)) {
      return;
    }
    PublicKeyVerify verifier = newVerifier(verifyCase.keyName);
    byte[] signature = Base64.getDecoder().decode(verifyCase.signature);
    signature[0] ^= 0x01;
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, signData));
  }

  @Test
  public void verifyFailsForDifferentMlDsaAlgorithm() throws Exception {
    Assume.assumeTrue(mlDsaSupported());
    PublicKeyVerify verifier65 = newVerifier(KEY_NAME_ML_DSA_65);
    byte[] signature44 = Base64.getDecoder().decode(ML_DSA_44_SIGNATURE);
    byte[] signature87 = Base64.getDecoder().decode(ML_DSA_87_SIGNATURE);
    assertThrows(GeneralSecurityException.class, () -> verifier65.verify(signature44, signData));
    assertThrows(GeneralSecurityException.class, () -> verifier65.verify(signature87, signData));

    PublicKeyVerify verifier87 = newVerifier(KEY_NAME_ML_DSA_87);
    byte[] signature65 = Base64.getDecoder().decode(ML_DSA_65_SIGNATURE);
    assertThrows(GeneralSecurityException.class, () -> verifier87.verify(signature65, signData));
  }

  @Test
  public void verifyFailsForInvalidSignature() throws Exception {
    PublicKeyVerify verifier = newVerifier(KEY_NAME_RSA_PSS_2048_SHA256);
    byte[] signature = Base64.getDecoder().decode(RSA_PSS_2048_SHA256_SIGNATURE);
    signature[0] ^= 0x01;
    assertThrows(GeneralSecurityException.class, () -> verifier.verify(signature, signData));
  }

  @Test
  public void verifyFailsForWrongData() throws Exception {
    PublicKeyVerify verifier = newVerifier(KEY_NAME_ECDSA_P256);
    byte[] signature = Base64.getDecoder().decode(ECDSA_P256_SIGNATURE);
    assertThrows(
        GeneralSecurityException.class,
        () -> verifier.verify(signature, "wrong data".getBytes(UTF_8)));
  }

  @Test
  public void keyNameInWrongFormat() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () ->
                GcpKmsPublicKeyVerify.builder()
                    .setKeyName(KEY_NAME_WRONG_FORMAT)
                    .setKeyManagementServiceClient(kmsClient)
                    .build());
    assertThat(e).hasMessageThat().contains("The keyName must follow");
  }

  @Test
  public void kmsClientNotGiven() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> GcpKmsPublicKeyVerify.builder().setKeyName(KEY_NAME_ECDSA_P256).build());
    assertThat(e).hasMessageThat().contains("The KeyManagementServiceClient object is null");
  }

  @Test
  public void buildFailsWhenGetPublicKeyThrows() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class, () -> newVerifier(KEY_NAME_GET_PUBLIC_KEY_EXCEPTION));
    assertThat(e).hasMessageThat().contains("The KMS GetPublicKey failed");
  }

  @Test
  public void buildFailsForPublicKeyChecksumMismatch() throws Exception {
    GeneralSecurityException e =
        assertThrows(
            GeneralSecurityException.class,
            () -> newVerifier(KEY_NAME_PUBLIC_KEY_CHECKSUM_MISMATCH));
    assertThat(e).hasMessageThat().contains("The GetPublicKey checksum does not match");
  }

  @Test
  public void buildFailsForKeyNameMismatch() throws Exception {
    GeneralSecurityException e =
        assertThrows(GeneralSecurityException.class, () -> newVerifier(KEY_NAME_KEY_NAME_MISMATCH));
    assertThat(e).hasMessageThat().contains("The key name in the response does not match");
  }

  @Test
  public void buildFailsForUnsupportedAlgorithm() throws Exception {
    // A classical algorithm with no PEM mapping is rejected on the PEM path.
    assertThrows(GeneralSecurityException.class, () -> newVerifier(KEY_NAME_UNSUPPORTED_ALGORITHM));
    // Pre-hash SLH-DSA is detected as post-quantum but is not one of the algorithms the PQC keyset
    // builder supports, so it is rejected on the PQC path.
    assertThrows(GeneralSecurityException.class, () -> newVerifier(KEY_NAME_HASH_SLH_DSA));
  }

  @Test
  public void buildFailsWhenNothingIsSet() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> GcpKmsPublicKeyVerify.builder().build());
  }
}
