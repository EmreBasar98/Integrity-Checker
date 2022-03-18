import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;

class ichecker {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, KeyStoreException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, SignatureException, NoSuchProviderException, InvalidKeySpecException {
        Iterator<String> iterator = Arrays.stream(args).iterator();
        String operation = iterator.next();
        HelperMethods helperMethods = new HelperMethods(); //calling helper class so it is compiled

        //parsing the arguments according to the flags.
        HashMap<String,String> arguments = new HashMap<>();
        while (iterator.hasNext()) {
            switch (iterator.next()) {
                case "-l": arguments.put("log", iterator.next());break;
                case "-p": arguments.put("path", iterator.next());break;
                case "-h": arguments.put("hash", iterator.next());break;
                case "-c": arguments.put("cert", iterator.next());break;
                case "-k": arguments.put("private", iterator.next());break;
                case "-r": arguments.put("registry", iterator.next());break;
            }
        }

        //according to the operation call necessary class.
        switch (operation){
            case "createCert": new CreateCertification(arguments);break;
            case "createReg":  new CreateRegistry(arguments);break;
            case "check":      new CheckIntegrity(arguments);break;
            default: System.err.println("Command couldn't be recognized!");break;
        }
    }
}