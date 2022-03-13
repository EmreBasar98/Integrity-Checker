import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;
import java.sql.Timestamp;

public class CheckIntegrity {
    public CheckIntegrity(HashMap<String, String> arguments) throws IOException, CertificateException,
            NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String regFilePath = arguments.get("registry");
        String path = arguments.get("path");
        String logFilePath = arguments.get("log");
        String hashType = arguments.get("hash");
        String certificatePath = arguments.get("cert");
        ArrayList<String> fileContents = new ArrayList<>();
        String[] ret = getRegContentAndSignature(regFilePath, fileContents);
        String regContent = ret[0];
        String lastLine = ret[1];

        SimpleDateFormat sdf1 = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        FileWriter logFile = new FileWriter(logFilePath, true);

        byte[] signatureBytes = Base64.getDecoder().decode(lastLine);
        PublicKey publicKey = CertificateFactory.getInstance("X.509")
                .generateCertificate(new FileInputStream(certificatePath)).getPublicKey();

        boolean verification = verifySignature(regContent, hashType, regFilePath, publicKey, signatureBytes);
        System.out.println(verification);
        if (!verification) {
            System.out.println("[time_stamp]: Registry file verification failed!");
            logFile.write(sdf1.format(timestamp) + ": Registry file verification failed!\n");
            System.exit(1);
        }

        File folder = new File(path);
        HashMap<String, String> systemFiles = new HashMap<>();
        for (File fileEntry : Objects.requireNonNull(folder.listFiles())) {
            Scanner myReader = new Scanner(fileEntry);
            StringBuilder myContent = new StringBuilder();
            // Gerekirse Path klasörü otomatik
            // oluşturulacak ve dosya içerikleri
            // for ile okunacak
            ArrayList<String> myContentArray = new ArrayList<String>();
            while (myReader.hasNext()) {
                myContentArray.add(myReader.nextLine());
            }
            for (String line : myContentArray) {
                myContent.append(line);
            }
            String myHashedContent = Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance(hashType).digest(myContent.toString().getBytes(StandardCharsets.UTF_8)));
            systemFiles.put(fileEntry.getName(), myHashedContent);
        }

        String filePath;
        String contentHash;
        String[] lineSplitted;
        String[] pathSplitted;
        String fileName;
        Boolean isFileChanged = false;
        String seperator = Pattern.quote(File.separator);
        HashMap<String, String> regFiles = new HashMap<>();
        HashMap<String, String> filesPaths = new HashMap<>();
        for (String l : fileContents) {
            lineSplitted = l.split(" ");
            filePath = lineSplitted[0];
            contentHash = lineSplitted[1];
            pathSplitted = filePath.split(seperator);
            fileName = pathSplitted[pathSplitted.length - 1];
            filesPaths.put(fileName, filePath);
            regFiles.put(fileName, contentHash);
        }

        for (String key : systemFiles.keySet()) {
            if (!regFiles.containsKey(key)) {
                logFile.write(sdf1.format(timestamp) + ": " + filesPaths.get(key) + " is created\n");
                System.out.println("yeni key" + key);
                isFileChanged = true;
            } else {
                if (!regFiles.get(key).equals(systemFiles.get(key))) {
                    logFile.write(sdf1.format(timestamp) + ": " + filesPaths.get(key) + " is altered\n");
                    System.out.println("altered" + key);
                    isFileChanged = true;
                }
            }
        }

        for (String key : regFiles.keySet()) {
            if (!systemFiles.containsKey(key)) {
                logFile.write(sdf1.format(timestamp) + ": " + path + seperator + key + " is deleted\n");
                System.out.println("silinmiş key" + key);
                isFileChanged = true;
            }
        }

        if (!isFileChanged) {
            System.out.println("no change");
            logFile.write(sdf1.format(timestamp) + ": The directory is checked and no change is detected!\n");
        }
        logFile.close();

    }

    private String[] getRegContentAndSignature(String regFilePath, ArrayList<String> fileContents)
            throws FileNotFoundException {
        File file = new File(regFilePath);
        Scanner myReader = new Scanner(file);
        String lastLine = null;
        StringBuilder regContent = new StringBuilder();
        ArrayList<String> lines = new ArrayList<String>();
        while (myReader.hasNext()) {
            lines.add(myReader.nextLine());
        }
        for (String l : lines) {
            int index = lines.indexOf(l);
            if (index == lines.size() - 1) {
                lastLine = l;
            } else {
                fileContents.add(l);
                regContent.append(l);
            }
        }
        String[] ret = { regContent.toString(), lastLine };
        return ret;
    }

    private boolean verifySignature(String registryContent, String hashType, String registryPath, PublicKey publicKey,
            byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String hash = hashType.equals("SHA-256") ? "SHA256" : "MD5";

        Signature signature = Signature.getInstance(hash + "withRSA");
        signature.initVerify(publicKey);
        signature.update(String.valueOf(registryContent).getBytes());

        return signature.verify(signatureBytes);
    }
}
