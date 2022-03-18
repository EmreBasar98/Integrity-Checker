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
import java.util.StringJoiner;
import java.util.regex.Pattern;
import sun.security.tools.keytool.Main;

public class CreateCertification {
    public CreateCertification(HashMap<String, String> arguments) throws NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, IOException, KeyStoreException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, SignatureException, NoSuchProviderException {
        String certificatePath = arguments.get("cert");
        String prikeyPath = arguments.get("private");
        createAndStore(certificatePath, prikeyPath);
    }

    public void createAndStore(String certificatePath, String prikeyPath) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, KeyStoreException, CertificateException, SignatureException, NoSuchProviderException {
        //a caller method to create keypairs and certificate
        CertAndKeyGen certAndKeyGen = new CertAndKeyGen("RSA", "SHA256withRSA");
        certAndKeyGen.generate(2048);
        createAndStorePrivKey(certAndKeyGen, prikeyPath);
        generate(certAndKeyGen);
        generateCertificate(certificatePath);
    }

    public void createAndStorePrivKey(CertAndKeyGen keyPair, String prikeyPath) throws NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, IOException {
        //Store the generated private key in a file with an additional message.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivateKey().getEncoded());

        byte[] additional = "This is private key file".getBytes();
        byte[] privateKeyInfo = pkcs8EncodedKeySpec.getEncoded();
        byte[] plaintext = new byte[additional.length + privateKeyInfo.length];

        System.arraycopy(privateKeyInfo, 0, plaintext, 0, privateKeyInfo.length);
        System.arraycopy(additional, 0, plaintext, privateKeyInfo.length, additional.length);

        byte[] passBytes = HelperMethods.prepareUserPassword();

        AES aes = new AES(passBytes);
        HelperMethods.createFile(prikeyPath);
        FileWriter prikeyFile = new FileWriter(prikeyPath);
        prikeyFile.write(new String(aes.encrypt(plaintext)));
        prikeyFile.close();
    }

    public void generate(CertAndKeyGen keypair)
            throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException,
            InvalidKeyException, SignatureException {
        //Method to create a keystore for created keypair. This keypair file is going o be used later for certificate creation.
        char[] psw = "password".toCharArray();
        OutputStream fout = null;

        try {
            fout = new java.io.FileOutputStream("keystore.p12");

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, psw);

            X500Name x500Name = new X500Name("CN=EMRE");

            PrivateKey privateKey = keypair.getPrivateKey();

            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = keypair.getSelfCertificate(x500Name, 35000 * 24L * 60L * 60L);
            //stroing the key pair in keystore
            keyStore.setKeyEntry("keypair", privateKey, "password".toCharArray(), chain);
            keyStore.store(fout, psw);
        } finally {
            if (fout != null) {
                fout.close();
            }
        }
    }

    private void execute(String command) {
        //en executer for keytool
        try {
            Main.main(command.trim().split("\\s+"));
        } catch (Exception e) {
            System.out.println("ERROR, keytool command could not be executed!");
        }
    }

    private void generateCertificate(String certificatePath) throws IOException {
        HelperMethods.createFile(certificatePath);
        //Generating a request for certificate signing using keytool
        execute(" -certreq" +
                " -alias keypair" +
                " -storetype PKCS12" +
                " -file request.csr" +
                " -storepass password" +
                " -keystore keystore.p12" +
                " -sigalg SHA256withRSA");

        //Generating X.509 public certificate with generated request
        execute(" -gencert" +
                " -validity 365" +
                " -keystore keystore.p12" +
                " -alias keypair" +
                " -storetype PKCS12" +
                " -infile request.csr" +
                " -storepass password" +
                " -sigalg SHA256withRSA" +
                " -outfile " + certificatePath);

        //Deleting keypair and request files for not letting them conflict with further runs.
        Files.deleteIfExists(FileSystems.getDefault().getPath("keypair.p12"));
        Files.deleteIfExists(FileSystems.getDefault().getPath("request.csr"));
    }
}
