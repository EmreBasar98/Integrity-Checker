import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class CreateRegistry {
    public CreateRegistry(HashMap<String, String> arguments) throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {

        String regFilePath = arguments.get("registry");
        String path = arguments.get("path");
        String logFile = arguments.get("log");
        String hash = arguments.get("hash");
        String priKey = arguments.get("private");

        byte[] plaintext = decryptPrivateKey(priKey);

//        String plaintextAsString = new String(plaintext, StandardCharsets.UTF_8);
//
//        System.out.println(plaintextAsString.contains("This is private key file"));
//
//        plaintextAsString = plaintextAsString.replace("This is private key file", "");
//        byte[] privKey = plaintextAsString.getBytes(StandardCharsets.UTF_8);
//
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privKey);
//
//        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
//
//        System.out.println(privateKey.getEncoded());
        byte[] additional = "This is private key file".getBytes();
        int prikeyinfoend = plaintext.length - additional.length;

        byte[] privateKeyInfo = new byte[prikeyinfoend];
        byte[] additionalCheck = new byte[additional.length];

        System.arraycopy(plaintext,0,privateKeyInfo,0,prikeyinfoend);
        System.arraycopy(plaintext,prikeyinfoend,additionalCheck,0,additional.length);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyInfo);

        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
        System.out.println(Arrays.toString(privateKey.getEncoded()));
    }

    public void createRegFile(String regFilePath, String path, String hash) throws IOException, NoSuchAlgorithmException {
        FileWriter regFile = new FileWriter(regFilePath);
        File folder = new File(path);
        StringBuilder regFileContent = new StringBuilder();
        for (File fileEntry : Objects.requireNonNull(folder.listFiles())) {
            Scanner myReader = new Scanner(fileEntry);
            String myContent = myReader.nextLine();//Gerekirse Path klasörü otomatik oluşturulacak ve dosya içerikleri for ile okunacak

            byte[] myHashedContent = MessageDigest.getInstance(hash).digest(myContent.getBytes());
            regFileContent.append(fileEntry.getPath() + " " + myHashedContent);
            regFile.write(fileEntry.getPath() + " " + myHashedContent+"\n");
        }
        byte[] regFileSignature = MessageDigest.getInstance(hash).digest(String.valueOf(regFileContent).getBytes());
        regFile.write(String.valueOf(regFileSignature));
        regFile.close();
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

    public byte[] decryptPrivateKey(String priKey) throws FileNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        File file = new File(priKey);
        Scanner myReader = new Scanner(file);
        byte[] ciphertext = myReader.nextLine().getBytes(StandardCharsets.UTF_8);
        byte[] pw = prepareUserPassword();
        AES aes = new AES(pw);
        byte[] plaintext = aes.decrypt(ciphertext);
        return plaintext;
    }

//    private String signature(StringBuilder registryContent, String hashType)
//            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, SignatureException {
//        //Specifying hash type
//        String hash = hashType.equals("SHA-256")?"SHA256":"MD5";
//
//        //Generating signature with the private key
//        Signature signature = Signature.getInstance(hash+"withRSA");
//        signature.initSign();
//        signature.update(registryContent.toString().getBytes());
//
//        return Base64.getEncoder().encodeToString(signature.sign());
//    }
}
