import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;
import java.util.StringJoiner;
import java.util.regex.Pattern;

public class HelperMethods {


    public static String convertToBinary(String s) {
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

    public static String stringPadding(String s) {
        StringBuilder sBuilder = new StringBuilder(s);
        while (sBuilder.length() < 512) {
            sBuilder.append("01");
        }
        s = sBuilder.toString();
        return s;
    }

    public static byte[] prepareUserPassword() throws NoSuchAlgorithmException {
        System.out.print("Enter a password: ");
        Scanner askForPassword = new Scanner(System.in);
        String password = askForPassword.nextLine();
        askForPassword.close();
        String bitPW = convertToBinary(password);
        String paddedBitPW = stringPadding(bitPW);
        return MessageDigest.getInstance("MD5").digest(paddedBitPW.getBytes());
    }

    public static String createFolderPath(String[] pathArray) {
        StringJoiner joiner = new StringJoiner(File.separator);
        for (String s: pathArray) {
            joiner.add(s);
        }
        return joiner.toString();
    }

    public static Object[] popLastElement(String[] oldArr) {
        String last = oldArr[oldArr.length - 1];
        String[] newArr = Arrays.copyOfRange(oldArr, 0, oldArr.length - 1);
        return new Object[]{newArr, last};
    }

    public static void createFile(String path) throws IOException {
        String seperator = Pattern.quote(File.separator);
        String[] pathSplitted = path.split(seperator);
        if (pathSplitted.length > 1) {
            Object[] ret = popLastElement(pathSplitted);
            String[] pathArray = (String[]) ret[0];
            String folferPath = createFolderPath(pathArray);
            new File(folferPath).mkdirs();
        }
    }
}
