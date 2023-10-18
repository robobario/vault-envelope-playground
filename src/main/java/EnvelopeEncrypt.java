import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.testcontainers.vault.VaultContainer;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Random;

public class EnvelopeEncrypt {
    private static final String AES = "AES";
    private static final int IV_SIZE_BYTES = 16;
    public static final int KEY_SIZE_BITS = 128;
    private static final String JCE_PROVIDER = "SunJCE";
    public static final String AES256_GCM_NOPADDING = "AES_256/GCM/NoPadding";
    private static final Random random = new SecureRandom();
    record DataKey(String keyEncryptionKeyId, int version, String datakeyCipherText, String datakeyPlainText, SecretKey secretKey){};
    record EncryptedRecord(String keyEncryptionKeyId, int version, String datakeyCipherText, String payloadCiphertextBase64, byte[] iv){};
    public static final String VAULT_TOKEN = "VAULT_TOKEN!";
    public static final String SECRET_KEY_ID = "my-key";
    public static VaultContainer<?> vaultContainer = new VaultContainer<>("hashicorp/vault:1.15")
            .withVaultToken(VAULT_TOKEN)
            .withInitCommand(
                    "secrets enable transit",
                    "write -f transit/keys/" + SECRET_KEY_ID
            );

    public static void main(String[] args) throws Exception {
        vaultContainer.start();
        final VaultConfig config = new VaultConfig()
                .address(vaultContainer.getHttpHostAddress())
                .token(VAULT_TOKEN)
                .build();

        // this is a bit odd, you have to force the secret engineVersion to 1 or else it mangles
        // the transit URL paths converting them to `http://localhost:32814/v1/transit/data/keys/my-key`
        // I think this is more a problem with the client assuming we want to work with the secrets API
        // We will probably use an HTTP client directly to avoid all these blocking ops anyway.
        int engineVersion = 1;
        final Vault vault = Vault.create(config, engineVersion);


        DataKey dataKey1 = createDataKey(vault, SECRET_KEY_ID);
        DataKey dataKey2 = createDataKey(vault, SECRET_KEY_ID);

        EncryptedRecord record1 = encrypt(dataKey1, "payload of Apples".getBytes(StandardCharsets.UTF_8));
        EncryptedRecord record2 = encrypt(dataKey2, "payload of Bananas".getBytes(StandardCharsets.UTF_8));

        rotateKey(vault, SECRET_KEY_ID);

        DataKey dataKey3 = createDataKey(vault, SECRET_KEY_ID);
        EncryptedRecord record3 = encrypt(dataKey3, "payload of Kiwifruit".getBytes(StandardCharsets.UTF_8));

        byte[] decrypted = decrypt(record1, vault);
        System.out.println("Decrypted record1: " + new String(decrypted));
        byte[] decrypted2 = decrypt(record2, vault);
        System.out.println("Decrypted record2: " + new String(decrypted2));

        // record3 was encrypted with a datakey created after rotation
        byte[] decrypted3 = decrypt(record3, vault);
        System.out.println("Decrypted record3: " + new String(decrypted3));

    }

    private static void rotateKey(Vault vault, String secretKeyId) throws VaultException {
        LogicalResponse write = vault.logical().write("transit/keys/" + secretKeyId + "/rotate", Map.of());
        int status = write.getRestResponse().getStatus();
        if(status != 200) {
            System.out.println("failed to decrypt datakey with status " + status + "! failed response");
            System.out.println(new String(write.getRestResponse().getBody(), StandardCharsets.UTF_8));
            System.exit(1);
        }
    }

    private static byte[] decrypt(EncryptedRecord encryptedRecord, Vault vault) {
        try {
            byte[] iv = encryptedRecord.iv;
            DataKey key = obtainDataKey(vault, encryptedRecord.datakeyCipherText, encryptedRecord.keyEncryptionKeyId,  encryptedRecord.version);
            System.out.println("DataKey reconstituted from vault: " + key);
            Cipher cipher = createDecryptionCipher(AES256_GCM_NOPADDING, key.secretKey, iv);
            String cipherTextBase64 = encryptedRecord.payloadCiphertextBase64;
            return cipher.doFinal(Base64.getDecoder().decode(cipherTextBase64));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static DataKey obtainDataKey(Vault vault, String datakeyCipherText, String keyEncryptionKeyId, int version) throws VaultException {
        LogicalResponse write = vault.logical().write("transit/decrypt/" + keyEncryptionKeyId, Map.of("ciphertext", datakeyCipherText));
        int status = write.getRestResponse().getStatus();
        if(status != 200) {
            System.out.println("failed to decrypt datakey with status " + status + "! failed response");
            System.out.println(new String(write.getRestResponse().getBody(), StandardCharsets.UTF_8));
            System.exit(1);
        }
        return new DataKey(keyEncryptionKeyId, version, datakeyCipherText, write.getData().get("plaintext"), base64Decode(write.getData().get("plaintext")));
    }

    private static EncryptedRecord encrypt(DataKey dataKey, byte[] plaintextPayload) {
        try {
            byte[] iv = createIV();
            Cipher cipher = createEncryptionCipher(AES256_GCM_NOPADDING, dataKey.secretKey, iv);
            byte[] payloadCipherText = cipher.doFinal(plaintextPayload);
            EncryptedRecord encryptedRecord = new EncryptedRecord(dataKey.keyEncryptionKeyId, dataKey.version, dataKey.datakeyCipherText, Base64.getEncoder().encodeToString(payloadCipherText), iv);
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

    private static DataKey createDataKey(Vault vault, String keyEncryptionKeyId) throws VaultException {
        LogicalResponse createDataKey = vault.logical().write("transit/datakey/plaintext/" + keyEncryptionKeyId, Map.of("bits", "256"));
        // very helpful, when the server returns 400 it returns a LogicalResponse with empty data, you have to dig into
        // the rest response to find out if the thing actually worked.
        int status = createDataKey.getRestResponse().getStatus();
        if(status != 200) {
            System.out.println("failed to get datakey with status " + status + "! failed response");
            System.out.println(new String(createDataKey.getRestResponse().getBody(), StandardCharsets.UTF_8));
            System.exit(1);
        }
        Map<String, String> data = createDataKey.getData();
        String plaintext = data.get("plaintext");
        String ciphertext = data.get("ciphertext");
        // not sure what this key_version is or if it's useful
        // edit: this looks like the version of the KEK, it goes up when you rotate, it is present in the ciphertext too
        // so you only need the ciphertext
        String keyVersion = data.get("key_version");
        DataKey dataKey = new DataKey(keyEncryptionKeyId, Integer.parseInt(keyVersion), ciphertext, plaintext, base64Decode(plaintext));
        System.out.println("DataKey created with vault for keyEncryptionKeyId " + keyEncryptionKeyId + ": " +dataKey);
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
