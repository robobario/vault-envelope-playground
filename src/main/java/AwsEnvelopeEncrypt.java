import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Random;

public class AwsEnvelopeEncrypt {
    private static final String AES = "AES";
    private static final int IV_SIZE_BYTES = 16;
    public static final int KEY_SIZE_BITS = 128;
    private static final String JCE_PROVIDER = "SunJCE";
    public static final String AES256_GCM_NOPADDING = "AES_256/GCM/NoPadding";
    private static final Random random = new SecureRandom();

    record DataKey(String keyEncryptionKeyId, String datakeyCipherTextBase64, String datakeyPlainText,
                   SecretKey secretKey) {
    }

    record EncryptedRecord(String keyEncryptionKeyId, String datakeyCipherTextBase64, String payloadCiphertextBase64,
                           byte[] iv) {
    }

    static DockerImageName localstackImage = DockerImageName.parse("localstack/localstack:0.11.3");

    public static LocalStackContainer localstack = new LocalStackContainer(localstackImage)
            .withServices(
                    LocalStackContainer.Service.KMS
            );

    public static void main(String[] args) throws Exception {
        localstack.start();
        URI endpointOverride = localstack.getEndpointOverride(LocalStackContainer.Service.KMS);
        Region region = Region.of(localstack.getRegion());
        String accessKey = localstack.getAccessKey();
        String secretKey = localstack.getSecretKey();

        // in our real app we'd likely use KmsAsyncClient instead
        AwsBasicCredentials creds = AwsBasicCredentials.create(accessKey, secretKey);
        StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(creds);
        KmsClientBuilder kmsClientBuilder = KmsClient.builder()
                .endpointOverride(endpointOverride)
                .region(region)
                .credentialsProvider(credentialsProvider);

        try (KmsClient kmsClient = kmsClientBuilder.build()) {
            CreateKeyResponse key = kmsClient.createKey();
            String keyId = key.keyMetadata().keyId();
            System.out.println(key);

            DataKey dataKey1 = createDataKey(kmsClient, keyId);
            DataKey dataKey2 = createDataKey(kmsClient, keyId);

            EncryptedRecord record1 = encrypt(dataKey1, "payload of Apples".getBytes(StandardCharsets.UTF_8));
            EncryptedRecord record2 = encrypt(dataKey2, "payload of Bananas".getBytes(StandardCharsets.UTF_8));

            byte[] decrypted = decrypt(record1, kmsClient);
            System.out.println("Decrypted record1: " + new String(decrypted));
            byte[] decrypted2 = decrypt(record2, kmsClient);
            System.out.println("Decrypted record2: " + new String(decrypted2));
        }
    }

    private static byte[] decrypt(EncryptedRecord encryptedRecord, KmsClient kms) {
        try {
            byte[] iv = encryptedRecord.iv;
            DataKey key = obtainDataKey(kms, encryptedRecord.datakeyCipherTextBase64, encryptedRecord.keyEncryptionKeyId);
            System.out.println("DataKey reconstituted from KMS: " + key);
            Cipher cipher = createDecryptionCipher(AES256_GCM_NOPADDING, key.secretKey, iv);
            String cipherTextBase64 = encryptedRecord.payloadCiphertextBase64;
            return cipher.doFinal(Base64.getDecoder().decode(cipherTextBase64));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static DataKey obtainDataKey(KmsClient kms, String datakeyCipherTextBase64, String keyEncryptionKeyId) throws VaultException {
        DecryptResponse decrypt = kms.decrypt(DecryptRequest.builder().keyId(keyEncryptionKeyId).ciphertextBlob(SdkBytes.fromByteArray(Base64.getDecoder().decode(datakeyCipherTextBase64))).build());

        String plaintextBase64 = Base64.getEncoder().encodeToString(decrypt.plaintext().asByteArray());
        return new DataKey(keyEncryptionKeyId, datakeyCipherTextBase64, plaintextBase64, base64Decode(plaintextBase64));
    }

    private static EncryptedRecord encrypt(DataKey dataKey, byte[] plaintextPayload) {
        try {
            byte[] iv = createIV();
            Cipher cipher = createEncryptionCipher(AES256_GCM_NOPADDING, dataKey.secretKey, iv);
            byte[] payloadCipherText = cipher.doFinal(plaintextPayload);
            EncryptedRecord encryptedRecord = new EncryptedRecord(dataKey.keyEncryptionKeyId, dataKey.datakeyCipherTextBase64, Base64.getEncoder().encodeToString(payloadCipherText), iv);
            System.out.println(encryptedRecord);
            return encryptedRecord;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey base64Decode(String key64) {
        byte[] decodedKey = Base64.getDecoder().decode(key64);
        // we assume AES
        return createAesSecretKey(decodedKey);
    }

    public static SecretKey createAesSecretKey(byte[] decodedKey) {
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, AES);
    }


    private static byte[] createIV() {
        byte[] buf = new byte[IV_SIZE_BYTES];
        random.nextBytes(buf);
        return buf;
    }

    private static DataKey createDataKey(KmsClient client, String keyEncryptionKeyId) throws VaultException {
        GenerateDataKeyResponse response = client.generateDataKey(GenerateDataKeyRequest.builder().keyId(keyEncryptionKeyId).numberOfBytes(32).build());
        String plaintext = Base64.getEncoder().encodeToString(response.plaintext().asByteArray());
        String ciphertext = Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray());
        DataKey dataKey = new DataKey(keyEncryptionKeyId, ciphertext, plaintext, base64Decode(plaintext));
        System.out.println("DataKey created with vault for keyEncryptionKeyId " + keyEncryptionKeyId + ": " + dataKey);
        return dataKey;
    }

    private static Cipher createEncryptionCipher(String transformation, Key key, byte[] iv)
            throws GeneralSecurityException {
        return createCipher(Cipher.ENCRYPT_MODE, transformation, key, iv);
    }

    private static Cipher createDecryptionCipher(String transformation, Key key, byte[] iv)
            throws GeneralSecurityException {
        return createCipher(Cipher.DECRYPT_MODE, transformation, key, iv);
    }

    private static Cipher createCipher(int mode, String transformation, Key key, byte[] iv)
            throws GeneralSecurityException {
        if (iv == null || iv.length == 0) {
            throw new GeneralSecurityException("Initialization vector either null or empty.");
        }
        Cipher cipher = Cipher.getInstance(transformation, JCE_PROVIDER);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(KEY_SIZE_BITS, iv);
        cipher.init(mode, key, gcmSpec);
        return cipher;
    }


}
