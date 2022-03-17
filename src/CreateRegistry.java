import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import java.sql.Timestamp;
import java.util.regex.Pattern;

public class CreateRegistry {
    public CreateRegistry(HashMap<String, String> arguments) throws NoSuchAlgorithmException, IOException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            InvalidKeySpecException, SignatureException, CertificateException {

        String regFilePath = arguments.get("registry");
        String path = arguments.get("path");
        String logFile = arguments.get("log");
        String hash = arguments.get("hash");
        String priKey = arguments.get("private");

        byte[] plaintext = decryptPrivateKey(priKey);
        PrivateKey privateKey = getPrivateKey(plaintext);
        createRegFile(regFilePath, path, hash, privateKey, logFile);
    }

    public void createRegFile(String regFilePath, String path, String hash, PrivateKey privateKey, String logFilePath)
            throws IOException, NoSuchAlgorithmException, SignatureException, InvalidKeyException,
            CertificateException {
        SimpleDateFormat sdf1 = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        HelperMethods.createFile(regFilePath);
        HelperMethods.createFile(logFilePath);
        FileWriter logFile = new FileWriter(logFilePath);
        FileWriter regFile = new FileWriter(regFilePath);
        StringBuilder regFileContent = new StringBuilder();
        logFile.write(sdf1.format(timestamp) + ": Registry file is created at " + path + "!\n");
        File folder = new File(path);

        int fileCounter = 0;
        for (File fileEntry : Objects.requireNonNull(folder.listFiles())) {
            Scanner myReader = new Scanner(fileEntry);
            StringBuilder myContent = new StringBuilder();

            ArrayList<String> myContentArray = new ArrayList<String>();
            while (myReader.hasNext()) {
                myContentArray.add(myReader.nextLine());
            }
            for (String line : myContentArray) {
                myContent.append(line);
            }
            String myHashedContent = Base64.getEncoder()
                    .encodeToString(MessageDigest.getInstance(hash)
                            .digest(myContent.toString().getBytes(StandardCharsets.UTF_8)));

            String fileInfo = fileEntry.getPath() + " " + myHashedContent;

            regFileContent.append(fileInfo);
            regFile.write(fileInfo + "\n");

            logFile.write(sdf1.format(timestamp) + ": " + fileEntry.getPath() + " is added to registry\n");
            fileCounter += 1;
        }
        String regFileSignature = signature(regFileContent, hash, privateKey);
        regFileContent.append(regFileSignature);
        regFile.write(regFileSignature);

        logFile.write(sdf1.format(timestamp) + ": " + fileCounter
                + " files are added to the registry and registry creation is finished!\n");
        regFile.close();
        logFile.close();
    }

    public byte[] decryptPrivateKey(String priKey) throws IOException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        File file = new File(priKey);
        Scanner myReader = new Scanner(file);
        byte[] ciphertext = myReader.nextLine().getBytes(StandardCharsets.UTF_8);
        byte[] pw = HelperMethods.prepareUserPassword();
        AES aes = new AES(pw);
        byte[] plaintext;
        try {
            plaintext = aes.decrypt(ciphertext);
        } catch (Exception e) {
            System.out.println("Wrong Password");
            plaintext = decryptPrivateKey(priKey);
        }
        return plaintext;
    }

    public PrivateKey getPrivateKey(byte[] plaintext) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] additional = "This is private key file".getBytes();
        int privKeyLen = plaintext.length - additional.length;
        byte[] privateKeyInfo = Arrays.copyOfRange(plaintext, 0, privKeyLen);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyInfo);

        return keyFactory.generatePrivate(privateKeySpec);
    }

    private String signature(StringBuilder registryContent, String hashType, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, SignatureException,
            CertificateException, FileNotFoundException, UnsupportedEncodingException {
        String hash = hashType.equals("SHA-256") ? "SHA256" : "MD5";

        byte[] data = registryContent.toString().getBytes(StandardCharsets.UTF_8);

        Signature signature = Signature.getInstance(hash + "withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        byte[] signatureBytes = signature.sign();

        return Base64.getEncoder().encodeToString(signatureBytes);
    }

}
