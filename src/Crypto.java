import java.io.*;
import java.io.File;
import java.util.*;
import java.util.Base64;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.nio.file.Files;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.concurrent.ThreadLocalRandom;

class Crypto {

    PublicKey sysK; // public key of whoever it's talking to
    PublicKey pub;
    PrivateKey priv;
    PublicKey gKey;
    SecretKey aes;
    SecureRandom random;
    int AES_LENGTH = 128;
    byte[] iv = new BigInteger("2766407063173738325154464814828650299").toByteArray();
    ArrayList<byte[]> usedNonces = new ArrayList<byte[]>();
    byte[] randomKey; // shared key gen
    SecretKey veriK; // shared key for verification (Kb)

    // constructor
    Crypto() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        sysK = null;
        pub = null;
        priv = null;
        aes = null;
        veriK = null;
        random = new SecureRandom();
        // random.nextBytes(iv);
        randomKey = new byte[128];
    }

    /*
     *
     * ******** One Time Key Generation ********
     *
     */
    void setRandom() {
        random.nextBytes(randomKey);
    }

    byte[] getRandom() {
        return randomKey;
    }

    String byteToString(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    void setVeriK(SecretKey k) {
        veriK = k;
    }

    /*
     *
     * ******** Sequence Number Checking ********
     *
     */
    void checkSequence(byte[] seqByte, int expseq) {

        String seq = new String(seqByte);
        String expStr = new String(aesGroupEncrypt(Integer.toString(expseq), aes));
        //System.out.println(expseq);
        if (!seq.equals(expStr)) {
            System.out.println("SEQUENCE NUMBER MISMATCH!!");
            System.out.println("REORDER ATTACK DETECTED!!");
            System.out.println("Shutting down...");
            System.exit(0);
        }
    }

    /*
     *
     * ******** Lamport-like Key Handling ********
     *
     */

    byte[] createLamportSeed() {
        System.out.println("Creating lamport key...");
        SecretKey key = genAESKey();
        byte[] seed = key.getEncoded();
        System.out.println("Number of bytes is: " + seed.length);
        return seed;
    }

    byte[] hashSecretKey(byte[] seed, int n) {
        // System.out.println("Hashing key: " + new String(seed) + " " +n+ " times.");
        byte[] hashedSecret = seed;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (int i = 0; i < n; i++) {
                md.update(hashedSecret);
                hashedSecret = md.digest();
            }
        } catch (Exception e) {
            System.out.println("Error creating Lamport-Like group key: " + e);
        }
        return hashedSecret;
    }

    SecretKey makeAESKeyFromString(byte[] key) {
        // System.out.println("The number of bytes is: " + key.length);
        return new SecretKeySpec(key, "AES");
    }

    /*
     *
     * ******** RSA Public/Private Keys ********
     *
     */

    // create keys into key files if not generated already
    void setSystemKP(String filename) {
        System.out.println("No key files found! Generating " + filename + " RSA keypair file");
        KeyPair KP = genKP();
        PublicKey publicKey = KP.getPublic();
        PrivateKey privateKey = KP.getPrivate();
        System.out.println("Keypairs generated: Saving to file...");
        try {
            KeyFactory fact = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec _pub = fact.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec _priv = fact.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            saveToFile("./keys/" + filename + "public.key", _pub.getModulus(), _pub.getPublicExponent());
            saveToFile("./keys/" + filename + "private.key", _priv.getModulus(), _priv.getPrivateExponent());
            System.out.println("keys saved in " + filename);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e2) {
            e2.printStackTrace();
        } catch (IOException e3) {
            e3.printStackTrace();
        } catch (InvalidKeySpecException e4) {
            e4.printStackTrace();
        }
    }

    void saveGroupPK(String filename, PublicKey groupK) {
        try {
            KeyFactory fact = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec _pub = fact.getKeySpec(groupK, RSAPublicKeySpec.class);
            saveToFile("./keys/" + filename + "public.key", _pub.getModulus(), _pub.getPublicExponent());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e2) {
            e2.printStackTrace();
        } catch (IOException e3) {
            e3.printStackTrace();
        } catch (InvalidKeySpecException e4) {
            e4.printStackTrace();
        }
    }


    // set host public key
    void setPublicKey(String name) {
        try {
            this.pub = (PublicKey) readKeyFromFile("./keys/" + name + "public.key");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // set host private key
    void setPrivateKey(String name) {
        try {
            this.priv = (PrivateKey) readKeyFromFile("./keys/" + name + "private.key");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    PublicKey stringToPK(String s) {
        PublicKey k = null;

        try {
            byte[] data = Base64.getDecoder().decode((s.getBytes()));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            k = fact.generatePublic(spec);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e2) {
            e2.printStackTrace();
        }
        return k;
    }

    // return host public key
    PublicKey getPublic() {
        return this.pub;
    }

    // return host private key
    PrivateKey getPrivate() {
        return this.priv;
    }

    // set public key of whoever host is talking to
    void setSysK(Object o) {
        sysK = (PublicKey) o;
    }

    PublicKey getSysK() {
        return this.sysK;
    }

    /*
     *
     * ******** AES Symmetric Keys ********
     *
     */

    // generate AES key
    SecretKey genAESKey() {
        SecretKey key = null;
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
            keyGen.init(128);
            key = keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e2) {
            e2.printStackTrace();
        }
        this.aes = key;
        return key;
    }

    void setAESKey(String key) {
        aes = new SecretKeySpec(decode(key), "AES");
    }

    SecretKey getAESKey() {
        return aes;
    }

    /*
     *
     * ******** Encryption/Decryption ********
     *
     */

    // encryption
    byte[] encrypt(final String type, final String plaintext, final Key key) {
        if (type.contains("AES"))
            return aesEncrypt(plaintext);
        byte[] encrypted = null;
        try {
            final Cipher cipher = Cipher.getInstance(type);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encrypted = cipher.doFinal(plaintext.getBytes());
        } catch (Exception e) {
            System.out.println("The Exception is=" + e);
        }
        return encrypted;
    }

    // decryption
    String decrypt(final String type, final byte[] encrypted, final Key key) {
        if (type.contains("AES"))
            return aesDecrypt(encrypted);
        String decryptedValue = null;
        try {
            final Cipher cipher = Cipher.getInstance(type);
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedValue = new String(cipher.doFinal(encrypted));
        } catch (Exception e) {
            System.out.println("The Exception is=" + e);
            e.printStackTrace(System.err);
        }
        return decryptedValue;
    }

    byte[] aesEncrypt(final String plaintext) {
        byte[] encrypted = null;
        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, aes, new IvParameterSpec(iv));
            encrypted = cipher.doFinal(plaintext.getBytes());
        } catch (Exception e) {
            System.out.println("The Exception is=" + e);
        }

        return encrypted;
    }

    byte[] aesGroupEncrypt(final String plaintext, final Key key) {
        byte[] encrypted = null;
        try {
            final Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            encrypted = cipher.doFinal(plaintext.getBytes());
        } catch (Exception e) {
            System.out.println("The Exception is=" + e);
        }
        return encrypted;
    }

    byte[] aesGroupDecrypt(final byte[] encrypted, final Key key) {
        byte[] decryptedValue = null;
        try {
            final Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            decryptedValue = cipher.doFinal(encrypted);
        } catch (Exception e) {
            System.out.println("The Exception is=" + e);
            e.printStackTrace(System.err);
        }
        return decryptedValue;
    }

    byte[] decode(String key) {
        return Base64.getDecoder().decode(key);
    }

    String aesDecrypt(final byte[] encrypted) {
        // iv = readBytesFromFile("./iv.txt");
        String decryptedValue = null;
        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, aes, new IvParameterSpec(iv));
            decryptedValue = new String(cipher.doFinal(encrypted));
        } catch (Exception e) {
            System.out.println("The Exception is=" + e);
            e.printStackTrace(System.err);
        }
        return decryptedValue;
    }

    byte[] createEncryptedString(ArrayList<String> params) {
        String concat = new String();
        for (int i = 0; i < params.size(); i++) {
            concat += params.get(i);
            if (i != params.size() - 1) {
                concat += "-";
            }
        }
        return encrypt("AES", concat, aes);
    }

    /*
     * ******** SHA256/Signature/HMAC ********
     */

    byte[] createChecksum(String data) {
        byte[] hash = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(data.getBytes("UTF-8"));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return hash;
    }

    byte[] signChecksum(byte[] checksum) {
        byte[] sigBytes = null;
        try {
            Signature sig = Signature.getInstance("SHA256withRSA"); // sign
            sig.initSign(priv); // sign with private key
            sig.update(checksum); // input checksum
            sigBytes = sig.sign(); // sign
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e2) {
            e2.printStackTrace();
        } catch (InvalidKeyException e3) {
            e3.printStackTrace();
        }
        return sigBytes;
    }

    boolean verifySignature(byte[] checksum, byte[] signChecksum) {
        boolean verify = false;
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(sysK);
            sig.update(checksum);
            verify = sig.verify(signChecksum);
        } catch (Exception e) {
            System.out.println("EXCEPTION VERIFYING SIGNATURE: " + e);
        }
        if (verify) {
            System.out.printf("Signature verified!\n");
        } else {
            System.out.println("Signarture verification issue.\n");
        }
        return verify;
    }

    boolean verifyfsMac(byte[] checksum, byte[] signChecksum, PublicKey gs) {
        boolean verify = false;
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(gs);
            sig.update(checksum);
            verify = sig.verify(signChecksum);
        } catch (Exception e) {
            System.out.println("EXCEPTION VERIFYING FSMAC SIGNATURE: " + e);
        }
        if (verify) {
            System.out.printf("Signature verified!\n");
        } else {
            System.out.println("Signarture verification issue.\n");
        }
        return verify;
    }

    byte[] createHmac(byte[] macBytes) {
        byte[] out = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256", "BC");
            mac.init(veriK);
            mac.update(macBytes);
            out = mac.doFinal();
        } catch (Exception e) {
            System.out.println("EXCEPTION CREATING HMAC: " + e);
        }
        return out;
    }

    byte[] createFileHmac(byte[] macBytes, SecretKey groupK) {
        byte[] out = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256", "BC");
            mac.init(groupK);
            mac.update(macBytes);
            out = mac.doFinal();
        } catch (Exception e) {
            System.out.println("EXCEPTION CREATING HMAC: " + e);
        }
        return out;
    }

    boolean verifyHmac(byte[] reverify, byte[] reOut) {
        byte[] out = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256", "BC");
            mac.init(veriK);
            mac.update(reverify);
            out = mac.doFinal();
        } catch (Exception e) {
            System.out.println("EXCEPTION VERIFYING HMAC: " + e);
        }
        if (Arrays.equals(reOut, out)) {
            System.out.println("HMAC Successfully verified!\n");
            return true;
        } else {
            System.out.println("Unable to verify HMAC. Is there a man in the middle??\n\n");
            return false;
        }
    }

    // used for fs client to verify that group sent
    byte[] createClientHmac(byte[] macBytes, PublicKey k) {
        byte[] out = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256", "BC");
            mac.init(k); // use client's key
            mac.update(macBytes);
            out = mac.doFinal();
        } catch (Exception e) {
            System.out.println("EXCEPTION CREATING HMAC: " + e);
        }
        return out;
    }

    boolean verifySignature(byte[] checksum, byte[] signChecksum, PublicKey k) {
        boolean verify = false;
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(k);
            sig.update(checksum);
            verify = sig.verify(signChecksum);
        } catch (Exception e) {
            System.out.println("EXCEPTION VERIFYING SIGNATURE: " + e);
        }
        if (verify) {
            System.out.printf("Signature verified!\n");
        } else {
            System.out.println("Unable to verify signature!\n");
        }
        return verify;
    }

    /*
     *
     * ******** TOKEN ********
     *
     */

    UserToken makeTokenFromString(String tokenString) {
        String[] tokenComps = tokenString.split(";");
        String issuer = tokenComps[0];
        String subject = tokenComps[1];
        long creationTime = Long.parseLong(tokenComps[2]);
        long expirationTime = Long.parseLong(tokenComps[3]);
        String fsIP = tokenComps[4];
        int fsPORT = Integer.parseInt(tokenComps[5]);
        List<String> groups = new ArrayList<>();
        for (int i = 6; i < tokenComps.length; i++) {
            groups.add(tokenComps[i]);
        }
        return new Token(issuer, subject, groups, creationTime, expirationTime, fsIP, fsPORT);
    }

    void verifyFServer(UserToken token, String ip, int port) {
        String tIP = token.getfsIP();
        int tPORT = token.getfsPORT();
        System.out.println("TIP is: " + tIP);
        System.out.println("TPORT is: " + tPORT);
        System.out.println("IP is: " + ip);
        System.out.println("Port is: " + port);
        if (!tIP.equals(ip)) {
            System.out.println("Stolen token detected; shutting down");
            System.exit(0);
        }
        if (tPORT != port) {
            System.out.println("Stolen token detected; shutting down");
            System.exit(0);
        }
    }
    /*
     *
     * ******** MISC. ********
     *
     */

    boolean isEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    String toString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    String toString(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    String RSAtoString(Key key) {
        return "------ BEGIN RSA PUBLIC KEY ------ \n" + Base64.getEncoder().encodeToString(key.getEncoded())
                + "\n------- END RSA PUBLIC KEY -------";
    }

    String getChallenge() {
        return Integer.toString(ThreadLocalRandom.current().nextInt(Integer.MIN_VALUE, -1));
    }

    /*
     *
     *
     * ******** Helper Methods ********
     *
     *
     */

    // Save keys to file
    private void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        System.out.println("Creating file: " + fileName);
        ObjectOutputStream oos = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oos.writeObject(mod);
            oos.writeObject(exp);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            oos.close();
        }
    }

    // generate RSA keypair
    private KeyPair genKP() {
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); // set RSA instance
            keyGen.initialize(2048); // set bit size
            keyPair = keyGen.genKeyPair(); // generate key pair
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
    }

    // Return the saved key from file
    private Key readKeyFromFile(String filename) throws IOException {
        InputStream in = new FileInputStream(filename);
        ObjectInputStream oin = new ObjectInputStream(new BufferedInputStream(in));
        Key key = null;
        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();
            KeyFactory fact = KeyFactory.getInstance("RSA");
            if (filename.contains("public"))
                key = fact.generatePublic(new RSAPublicKeySpec(m, e));
            else
                key = fact.generatePrivate(new RSAPrivateKeySpec(m, e));
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            oin.close();
        }
        return key;
    }

}
