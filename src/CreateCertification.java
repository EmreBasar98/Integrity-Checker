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
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;

public class CreateCertification {
    public CreateCertification(HashMap<String, String> arguments) throws NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, SignatureException, NoSuchProviderException {
        String certificatePath = arguments.get("cert");
        String prikeyPath = arguments.get("private");
        createAndStore(certificatePath, prikeyPath);

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

    public void createAndStore(String certificatePath, String prikeyPath) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, KeyStoreException, CertificateException, SignatureException, NoSuchProviderException {

        CertAndKeyGen certAndKeyGen = new CertAndKeyGen("RSA", "SHA256withRSA");
        certAndKeyGen.generate(2048);
        createAndStorePrivKey(certAndKeyGen, prikeyPath);
        generate(certAndKeyGen);
        generateCertificate(certificatePath);
    }

    public void createAndStorePrivKey(CertAndKeyGen keyPair, String prikeyPath) throws NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, IOException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivateKey().getEncoded());

        byte[] additional = "This is private key file".getBytes();
        byte[] privateKeyInfo = pkcs8EncodedKeySpec.getEncoded();
        byte[] plaintext = new byte[additional.length + privateKeyInfo.length];

        System.arraycopy(privateKeyInfo, 0, plaintext, 0, privateKeyInfo.length);
        System.arraycopy(additional, 0, plaintext, privateKeyInfo.length, additional.length);

        byte[] passBytes = prepareUserPassword();

        AES aes = new AES(passBytes);

        FileWriter prikeyFile = new FileWriter(prikeyPath);
        prikeyFile.write(new String(aes.encrypt(plaintext)));
        prikeyFile.close();
    }

    public void generate(CertAndKeyGen keypair)
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException,
            InvalidKeyException, SignatureException {


        char[] psw = "password".toCharArray();
        OutputStream fout = null;

        try {
            fout = new java.io.FileOutputStream("keypair.p12");

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, psw);

            X500Name x500Name = new X500Name("CN=EMRE");

            PrivateKey privateKey = keypair.getPrivateKey();
            System.out.println(Arrays.toString(privateKey.getEncoded()));
            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = keypair.getSelfCertificate(x500Name, 35000 * 24L * 60L * 60L);

            keyStore.setKeyEntry("keypair", privateKey, "password".toCharArray(), chain);

            keyStore.store(fout, psw);
        } finally {
            if (fout != null) {
                fout.close();
            }
        }

    }

    private void execute(String command) {
        //Using keytool
        try {
            sun.security.tools.keytool.Main.main(command.trim().split("\\s+"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void generateCertificate(String certificatePath) throws IOException {
        //Generating a Certificate Signing Request
        execute(" -certreq" +
                " -alias keypair" +
                " -dname CN=EMRE" +
                " -storetype PKCS12" +
                " -keypass password" +
                " -file request.csr" +
                " -storepass password" +
                " -keystore keypair.p12" +
                " -sigalg SHA256withRSA");

        //Generating X.509 public certificate
        execute(" -gencert" +
                " -rfc" +
                " -validity 365" +
                " -dname CN=EMRE" +
                " -alias keypair" +
                " -keypass password" +
                " -storetype PKCS12" +
                " -infile request.csr" +
                " -storepass password" +
                " -keystore keypair.p12" +
                " -sigalg SHA256withRSA" +
                " -outfile " + certificatePath);

        //Deleting keypair and request files, there are not needed anymore
        Files.deleteIfExists(FileSystems.getDefault().getPath("keypair.p12"));
        Files.deleteIfExists(FileSystems.getDefault().getPath("request.csr"));
    }
}
