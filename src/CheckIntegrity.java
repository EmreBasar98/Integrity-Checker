import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.regex.Pattern;

public class CheckIntegrity {
    public CheckIntegrity(HashMap<String, String> arguments) throws IOException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String regFilePath = arguments.get("registry");
        String path = arguments.get("path");
        String logFilePath = arguments.get("log");
        String hashType = arguments.get("hash");
        String certificatePath = arguments.get("cert");

        ArrayList<String> fileContents = new ArrayList<>();
        String[] ret = getRegContentAndSignature(regFilePath,fileContents);
        String regContent = ret[0];
        String lastLine = ret[1];

        byte[] signatureBytes = Base64.getDecoder().decode(lastLine);
        PublicKey publicKey = CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(certificatePath)).getPublicKey();

        boolean verification = verifySignature(regContent, hashType, regFilePath, publicKey, signatureBytes);
        System.out.println(verification);
        if (!verification){
            System.out.println("[time_stamp]: Registry file verification failed!");
            System.exit(1);
        }
//        public static boolean equals(byte[] a, byte[] a2)
        File folder = new File(path);
        HashMap<String, byte[]> fileBytes = new HashMap<>();
        for (File fileEntry : Objects.requireNonNull(folder.listFiles())) {
            Scanner myReader = new Scanner(fileEntry);
            String myContent = myReader.nextLine();
            System.out.println(hashType);
            MessageDigest md = MessageDigest.getInstance(hashType);
            System.out.println(md.hashCode());
            byte[] myHashedContent = md.digest(myContent.getBytes(StandardCharsets.UTF_8));

            fileBytes.put(fileEntry.getName(), myHashedContent);
        }


        String filePath;
        String contentHash;
        String[] lineSplitted;
        String[] pathSplitted;
        String fileName;
        HashMap<String, String> regFileBytes = new HashMap<>();
        for (String l: fileContents) {
            lineSplitted = l.split(" ");
            filePath = lineSplitted[0];
            contentHash = lineSplitted[1];
            pathSplitted = filePath.split(Pattern.quote(File.separator));
            fileName = pathSplitted[pathSplitted.length - 1];

            regFileBytes.put(fileName, contentHash);
        }


        for (String key: fileBytes.keySet()) {
            System.out.println(key + " "+ fileBytes.get(key));
        }

        System.out.println("-----------------------");
        for (String key: regFileBytes.keySet()) {
            System.out.println(key + " "+ regFileBytes.get(key));
        }
    }



    private String[] getRegContentAndSignature(String regFilePath, ArrayList<String> fileContents) throws FileNotFoundException {
        File file = new File(regFilePath);
        Scanner myReader = new Scanner(file);
        String lastLine = null;
        StringBuilder regContent = new StringBuilder();
        ArrayList<String> lines = new ArrayList<String>();
        while (myReader.hasNext()) {
            lines.add(myReader.nextLine());
        }
        for (String l: lines) {
            int index = lines.indexOf(l);
            if (index == lines.size() - 1) {
                lastLine = l;
            }
            else{
                fileContents.add(l);
                regContent.append(l);
            }
        }
        String[] ret = {regContent.toString(), lastLine};
        return ret;
    }

    private boolean verifySignature(String registryContent,String hashType,String registryPath, PublicKey publicKey, byte[] signatureBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String hash = hashType.equals("SHA-256")?"SHA256":"MD5";

        Signature signature = Signature.getInstance(hash+"withRSA");
        signature.initVerify(publicKey);
        signature.update(String.valueOf(registryContent).getBytes());

        return signature.verify(signatureBytes);
    }
}
