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
import java.util.Base64;
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

      String pem;
      CryptoKeyVersion.CryptoKeyVersionAlgorithm algorithm;
      switch (name) {
        case KEY_NAME_ECDSA_P384:
          pem = ECDSA_P384_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P384_SHA384;
          break;
        case KEY_NAME_RSA_PKCS1_2048_SHA256:
          pem = RSA_2048_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_2048_SHA256;
          break;
        case KEY_NAME_RSA_PKCS1_3072_SHA256:
          pem = RSA_3072_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_3072_SHA256;
          break;
        case KEY_NAME_RSA_PKCS1_4096_SHA256:
          pem = RSA_4096_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA256;
          break;
        case KEY_NAME_RSA_PKCS1_4096_SHA512:
          pem = RSA_4096_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512;
          break;
        case KEY_NAME_RSA_PSS_2048_SHA256:
          pem = RSA_2048_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_2048_SHA256;
          break;
        case KEY_NAME_RSA_PSS_3072_SHA256:
          pem = RSA_3072_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_3072_SHA256;
          break;
        case KEY_NAME_RSA_PSS_4096_SHA256:
          pem = RSA_4096_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA256;
          break;
        case KEY_NAME_RSA_PSS_4096_SHA512:
          pem = RSA_4096_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_4096_SHA512;
          break;
        case KEY_NAME_UNSUPPORTED_ALGORITHM:
          // The algorithm is rejected before the public key is parsed, so the PEM is never used.
          pem = ECDSA_P256_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_SECP256K1_SHA256;
          break;
        case KEY_NAME_ECDSA_P256:
        case KEY_NAME_PUBLIC_KEY_CHECKSUM_MISMATCH:
        case KEY_NAME_KEY_NAME_MISMATCH:
          pem = ECDSA_P256_PUBLIC_KEY;
          algorithm = CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256;
          break;
        default:
          responseObserver.onCompleted();
          return;
      }

      ByteString publicKey = ByteString.copyFromUtf8(pem);
      long crc32c = Hashing.crc32c().hashBytes(publicKey.asReadOnlyByteBuffer()).padToLong();
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
                      .setData(publicKey)
                      .setCrc32CChecksum(Int64Value.of(crc32c)))
              .build();
      responseObserver.onNext(response);
      responseObserver.onCompleted();
    }
  }

  @Before
  public void setUp() throws Exception {
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

  /** A classical (non-PQC) signature algorithm together with its key name and test signature. */
  private static final class ClassicalVerifyCase {
    final String keyName;
    final String signature;

    ClassicalVerifyCase(String keyName, String signature) {
      this.keyName = keyName;
      this.signature = signature;
    }

    @Override
    public String toString() {
      return keyName;
    }
  }

  @DataPoints("classicalVerifyCases")
  public static final ClassicalVerifyCase[] classicalVerifyCases =
      new ClassicalVerifyCase[] {
        new ClassicalVerifyCase(KEY_NAME_ECDSA_P256, ECDSA_P256_SIGNATURE),
        new ClassicalVerifyCase(KEY_NAME_ECDSA_P384, ECDSA_P384_SIGNATURE),
        new ClassicalVerifyCase(KEY_NAME_RSA_PKCS1_2048_SHA256, RSA_PKCS1_2048_SHA256_SIGNATURE),
        new ClassicalVerifyCase(KEY_NAME_RSA_PKCS1_3072_SHA256, RSA_PKCS1_3072_SHA256_SIGNATURE),
        new ClassicalVerifyCase(KEY_NAME_RSA_PKCS1_4096_SHA256, RSA_PKCS1_4096_SHA256_SIGNATURE),
        new ClassicalVerifyCase(KEY_NAME_RSA_PKCS1_4096_SHA512, RSA_PKCS1_4096_SHA512_SIGNATURE),
        new ClassicalVerifyCase(KEY_NAME_RSA_PSS_2048_SHA256, RSA_PSS_2048_SHA256_SIGNATURE),
        new ClassicalVerifyCase(KEY_NAME_RSA_PSS_3072_SHA256, RSA_PSS_3072_SHA256_SIGNATURE),
        new ClassicalVerifyCase(KEY_NAME_RSA_PSS_4096_SHA256, RSA_PSS_4096_SHA256_SIGNATURE),
        new ClassicalVerifyCase(KEY_NAME_RSA_PSS_4096_SHA512, RSA_PSS_4096_SHA512_SIGNATURE),
      };

  @Theory
  public void verifyWorksForClassicalAlgorithm(
      @FromDataPoints("classicalVerifyCases") ClassicalVerifyCase verifyCase) throws Exception {
    assertVerifies(verifyCase.keyName, verifyCase.signature);
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
    assertThrows(
        GeneralSecurityException.class, () -> newVerifier(KEY_NAME_GET_PUBLIC_KEY_EXCEPTION));
  }

  @Test
  public void buildFailsForPublicKeyChecksumMismatch() throws Exception {
    assertThrows(
        GeneralSecurityException.class, () -> newVerifier(KEY_NAME_PUBLIC_KEY_CHECKSUM_MISMATCH));
  }

  @Test
  public void buildFailsForKeyNameMismatch() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> newVerifier(KEY_NAME_KEY_NAME_MISMATCH));
  }

  @Test
  public void buildFailsForUnsupportedAlgorithm() throws Exception {
    assertThrows(GeneralSecurityException.class, () -> newVerifier(KEY_NAME_UNSUPPORTED_ALGORITHM));
  }
}
