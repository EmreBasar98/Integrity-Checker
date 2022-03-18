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

        //Loading the registry file content and signature
        ArrayList<String> fileContents = new ArrayList<>();
        String[] ret = getRegContentAndSignature(regFilePath, fileContents);
        String regContent = ret[0];
        String lastLine = ret[1];
        byte[] signatureBytes = Base64.getDecoder().decode(lastLine);

        SimpleDateFormat sdf1 = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
        FileWriter logFile = new FileWriter(logFilePath, true);

        //Loading the publickey from certificate
        PublicKey publicKey = CertificateFactory.getInstance("X.509")
                .generateCertificate(new FileInputStream(certificatePath)).getPublicKey();

        //Verification of the regFile signature
        boolean verification = verifySignature(regContent, hashType, regFilePath, publicKey, signatureBytes);
        if (!verification) {
            logFile.write(sdf1.format(timestamp) + ": Registry file verification failed!\n");
            System.exit(1);
        }
        //Loading the monitored path file contents  and hashing the contents to be compared with reg file hashes.
        File folder = new File(path);
        HashMap<String, String> systemFiles = new HashMap<>();
        HashMap<String, String> systemFilesPaths = new HashMap<>();
        for (File fileEntry : Objects.requireNonNull(folder.listFiles())) {
            Scanner myReader = new Scanner(fileEntry);
            StringBuilder myContent = new StringBuilder();

            systemFilesPaths.put(fileEntry.getName(), fileEntry.getPath());
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
        //Adjusting the reg File content to be compared with current file contents.
        String filePath;
        String contentHash;
        String[] lineSplitted;
        String[] pathSplitted;
        String fileName;
        boolean isFileChanged = false;
        String seperator = Pattern.quote(File.separator);
        HashMap<String, String> regFiles = new HashMap<>();
        HashMap<String, String> regFilesPaths = new HashMap<>();
        for (String l : fileContents) {
            lineSplitted = l.split(" ");
            filePath = lineSplitted[0];
            contentHash = lineSplitted[1];
            pathSplitted = filePath.split(seperator);
            fileName = pathSplitted[pathSplitted.length - 1];
            regFilesPaths.put(fileName, filePath);
            regFiles.put(fileName, contentHash);
        }
        //comparison and logging
        logFileChanges(systemFiles, regFiles, logFile, regFilesPaths, sdf1, isFileChanged, timestamp, systemFilesPaths);
        logFile.close();
    }

    private String[] getRegContentAndSignature(String regFilePath, ArrayList<String> fileContents)
            throws FileNotFoundException {
        //Load reg content and signature from file
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
        //verify the reg file signature using public key
        String hash = hashType.equals("SHA-256") ? "SHA256" : "MD5";

        Signature signature = Signature.getInstance(hash + "withRSA");
        signature.initVerify(publicKey);
        signature.update(String.valueOf(registryContent).getBytes());

        return signature.verify(signatureBytes);
    }

    private void logFileChanges(HashMap<String, String> systemFiles, HashMap<String, String> regFiles, FileWriter logFile,HashMap<String, String> regFilesPaths,
                                SimpleDateFormat sdf1, boolean isFileChanged, Timestamp timestamp, HashMap<String, String> systemFilesPaths) throws IOException {
        //comparing hash values of the file contents and according to that log the status.
        for (String key : systemFiles.keySet()) {
            if (!regFiles.containsKey(key)) {
                logFile.write(sdf1.format(timestamp) + ": " + systemFilesPaths.get(key) + " is created\n");
                isFileChanged = true;
            } else {
                if (!regFiles.get(key).equals(systemFiles.get(key))) {
                    logFile.write(sdf1.format(timestamp) + ": " + systemFilesPaths.get(key) + " is altered\n");
                    isFileChanged = true;
                }
            }
        }

        for (String key : regFiles.keySet()) {
            if (!systemFiles.containsKey(key)) {
                logFile.write(sdf1.format(timestamp) + ": " + regFilesPaths.get(key) + " is deleted\n");
                isFileChanged = true;
            }
        }

        if (!isFileChanged) {
            logFile.write(sdf1.format(timestamp) + ": The directory is checked and no change is detected!\n");
        }
    }
}
