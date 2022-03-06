import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;

public class CreateCertification {
    public CreateCertification(HashMap<String, String> arguments) throws NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, SignatureException, NoSuchProviderException {
        String certificatePath = arguments.get("cert");
        String prikeyPath = arguments.get("private");

        CertAndKeyGen certAndKeyGen = new CertAndKeyGen("RSA", "SHA256withRSA");
        certAndKeyGen.generate(2048);
//        KeyPair keyPair = new KeyPair(certAndKeyGen.getPublicKey(), certAndKeyGen.getPrivateKey());

        store(certAndKeyGen, prikeyPath);
        createAndStoreCertificate(certAndKeyGen, certificatePath);

    }

    public String convertToBinary(String s) {
        byte[] bytes = s.getBytes();
        StringBuilder binary = new StringBuilder();
        for (byte b : bytes) {
            int val = b;
            for (int i = 0; i < 8; i++) {
                binary.append((val & 128) == 0 ? 0 : 1);
                val <<= 1;
            }
        }
        return binary.toString();
    }

    public String stringPadding(String s) {
        StringBuilder sBuilder = new StringBuilder(s);
        while (sBuilder.length() < 512) {
            sBuilder.append("01");
        }
        s = sBuilder.toString();
        return s;
    }

    public byte[] prepareUserPassword() throws NoSuchAlgorithmException {
        System.out.print("Enter a password: ");
        Scanner askForPassword = new Scanner(System.in);
        String password = askForPassword.nextLine();
        askForPassword.close();
        String bitPW = convertToBinary(password);
        String paddedBitPW = stringPadding(bitPW);
        return MessageDigest.getInstance("MD5").digest(paddedBitPW.getBytes());
    }

    private void run(String command){
        try{ sun.security.tools.keytool.Main.main(command.trim().split("\\s+")); }
        catch (Exception e) { e.printStackTrace(); }
    }

    public void store(CertAndKeyGen keyPair, String prikeyPath) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException {
        createAndStorePrivKey(keyPair, prikeyPath);
    }

    public void createAndStorePrivKey(CertAndKeyGen keyPair, String prikeyPath) throws NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, IOException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivateKey().getEncoded());

        byte[] additional = "This is private key file".getBytes();
        byte[] privateKeyInfo = pkcs8EncodedKeySpec.getEncoded();
        byte[] plaintext = new byte[additional.length+privateKeyInfo.length];

        System.arraycopy(privateKeyInfo,0,plaintext,0,privateKeyInfo.length);
        System.arraycopy(additional,0,plaintext,privateKeyInfo.length,additional.length);

        byte[] passBytes = prepareUserPassword();

        AES aes = new AES(passBytes);

        FileWriter prikeyFile = new FileWriter(prikeyPath);
        prikeyFile.write(new String(aes.encrypt(plaintext))); prikeyFile.close();
    }

    public void createAndStoreCertificate(CertAndKeyGen keyPair, String certificatePath) throws IOException, CertificateException, SignatureException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
        X509Certificate[] chain = new X509Certificate[1];
        System.out.println(keyPair.getPrivateKey().getEncoded());
        chain[0] = keyPair.getSelfCertificate(new X500Name("CN=EMRE"), (long) 365 * 24 * 3600);
        System.out.println(chain[0].getSignature());
    }
}
