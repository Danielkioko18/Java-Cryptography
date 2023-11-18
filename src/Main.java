/*
    This is the main class to implement of KMACOF256 functionality
    This class implements all the necessary functionalities so as to give the required services
    *Moreover it implements most of the methods declared in the FileHash.java so as to meet the requirements
*/

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;


public class Main {
    /* 
        Main method which drives the whole application inside the main class
        drives all the methods inside this class and the FileHash class
    */
    public static void main(String[] args) {
        // scanner class to get user input
        Scanner userInput = new Scanner(System.in);
        int categoryResponse = selectCategoryPrompt(userInput);

        switch (categoryResponse) {
            case 1:
                //proceed to KMAC service selection if userinput is 2 
                do {
                    selectService(userInput);
                } while (repeat(userInput));
                userInput.close();
            case 2:
                //exit the app if the user input is 2
                System.out.println("====================== Exiting App ==========================");
        }

    }
    
    /* Secure random variable 
        generates secure random variable Z 
    */
    private static SecureRandom z = new SecureRandom();
    
    /* 
        initializing the class FileHash to create an object 
    */
    FileHash fHash = new FileHash();
    private static byte[] previousEncrypt;
    
    
    
    //select prompt mode
    private static int selectCategoryPrompt(final Scanner userIn) {
        String menuPrompt = "Please enter the corresponding number for the category of service you would like:\n" + "    1) SHA-3 Cryptographic Hashing\n" + "    2) Exit the App\n";
        int response = getIntInRange(userIn, menuPrompt, 1, 4);
        if (response == 1) {
            return 1;
        } else {
            return 2;
        }
    }
    
    //prompt for    KMAC  selections and input
    private static void selectService(final Scanner userInput) {
        String menu = "Please enter the corresponding number of the service you would like to use:\n" + "    1) Compute a plain cryptographic hash\n" + "    2) Compute an authentication tag (MAC)\n" + "    3) Encrypt a given data file\n" + "    4) Decrypt a given symmetric cryptogram\n";
        int response = getIntInRange(userInput, menu, 1, 4);
        switch (response) {
            case 1:
                plainHashService(inputPrompt(userInput));
                break;
            case 2:
                authenticationTagService(inputPrompt(userInput));
                break;
            case 3:
                encryptionService();
                break;
            default:
                decryptService(decryptPreviousCryptogram(userInput));
                break;
        }
    }
    
    
    /*
        file and input prompt functionality
        choose whether to input text or input file
    */
    private static String inputPrompt(Scanner userIn) {
        String menuPrompt = "What format would you like your input:\n" + "    1) File\n" + "    2) User input Text through command line\n";
        int input = getIntInRange(userIn, menuPrompt, 1, 2);
        if (input == 1) {
            return "file";
        } else {
            return "user input";
        }
    }
    
    //decrypting previous encryption
     private static String decryptPreviousCryptogram(Scanner userInput) {
        String menu = "What format would you like your input:\n" + "    1) Most recently encrypted (requires use of encryption service first).\n" + "    2) User input cryptogram\n";
        int input = getIntInRange(userInput, menu, 1, 2);
        if (input == 1) {
            return "prev encrypt";
        } else {
            return "user input";
        }
    }
    
    /*
        asking for repetition of the program from the user
        where user chooses whether to proceed or halt the program
    */
    private static boolean repeat(final Scanner userInput) {
        System.out.println("\nWould you like to use another service? (Y/N)");
        String s = userInput.next();
        System.out.println();
        return (s.equalsIgnoreCase("Y") || s.equalsIgnoreCase ("yes"));
    }
    
    
    //method for plain hash service
    private static void plainHashService(final String input) {
        //input should  be "file" or "user input"
        byte[] byteArray;
        String theString = null;
        Scanner userInput = new Scanner(System.in);

        if (input.equals("file")) { //input from given file
            File inputFile = getInputFile(userInput);
            theString = fileToString(inputFile);
        } else if (input.equals("user input")) { //input from command line
            System.out.println("Please enter a phrase to be hashed: ");
            theString = userInput.nextLine();
        }

        assert theString != null;
        byteArray = theString.getBytes();
        byteArray = FileHash.KMACXOF256("".getBytes(), byteArray, 512, "D".getBytes());
        System.out.println(FileHash.bytesToHexString(byteArray));
    }
    
    //authentication mac tag computation
    private static void authenticationTagService(final String input) {
        //get user input aas either "file" or "user input"
        byte[] byteArray;
        String theText = null;
        String passphrase = null;
        Scanner userInput = new Scanner(System.in);

        if (input.equals("file")) { //input from file
            File inFile = getInputFile(userInput);
            theText = fileToString(inFile);
        } else if (input.equals("user input")) { //input from command line
            System.out.println("Please enter the Text you want to be hashed: ");
            theText = userInput.nextLine();
        }

        System.out.println("Please enter a passphrase: ");
        passphrase = userInput.nextLine();
        assert theText != null;
        byteArray = theText.getBytes();
        byteArray = FileHash.KMACXOF256(passphrase.getBytes(), byteArray, 512, "T".getBytes());
        System.out.println(FileHash.bytesToHexString(byteArray));
    }
    
    //encryption method for encryptions
    private static void encryptionService() {
        Scanner userIn = new Scanner(System.in);
        File theFile = getInputFile(userIn);
        String theFileContent = fileToString(theFile);
        String thePassphrase;
        byte[] byteArray = theFileContent.getBytes();
        System.out.println("Please enter a passphrase: ");
        thePassphrase = userIn.nextLine();
        previousEncrypt = encryptKMAC(byteArray, thePassphrase);
        System.out.println(FileHash.bytesToHexString(previousEncrypt));
    }
    
    //decryprion  method to decrypt encrypted text to plain text
    private static void decryptService(String input) {
        Scanner userIn = new Scanner(System.in);
        String thePassphrase;
        byte[] decryptedByteArray = new byte[0];
        System.out.println("Please enter a passphrase you used for encryption: ");
        thePassphrase = userIn.nextLine();
        if (input.equals("prev encrypt")) { //input from file
            decryptedByteArray = decryptKMAC(previousEncrypt, thePassphrase);
        } else if (input.equals("user input")) { //input from command line
            System.out.println("\nPlease input a cryptogram in hex string format in one line (spaces okay, NO NEW LINES!!!!!): \n");
            String userString = userIn.nextLine();
            byte[] hexBytes = FileHash.hexStringToBytes(userString);
            decryptedByteArray = decryptKMAC(hexBytes, thePassphrase);
        }
        System.out.println("\nDecryption in Hex format:\n" + FileHash.bytesToHexString(decryptedByteArray));
        System.out.println("\nThe Plain Text:\n" + new String (decryptedByteArray, StandardCharsets.UTF_8));
    }
    
    //symetric encryption using KMAC
    private static byte[] encryptKMAC(byte[] m, String pw) {
        byte[] rand = new byte[64];
        z.nextBytes(rand);

        //squeeze bits from sponge
        byte[] keka = FileHash.KMACXOF256(FileHash.concat(rand, pw.getBytes()), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);
        
        byte[] c = FileHash.KMACXOF256(ke, "".getBytes(), (m.length * 8), "SKE".getBytes());
        c =  FileHash.xorBytes(c, m);
        byte[] t = FileHash.KMACXOF256(ka, m, 512, "SKA".getBytes());

        return FileHash.concat(FileHash.concat(rand, c), t);
    }
    
    //symetric cryptogram decryption functionality
    private static byte[] decryptKMAC(byte[] cryptogram, String pw) {
        byte[] rand = new byte[64];
        //get 512-bit random number from the beginning of cryptogram
        System.arraycopy(cryptogram, 0, rand, 0, 64);

        //retrieving the encrypted message of the previous encryption
        byte[] in = Arrays.copyOfRange(cryptogram, 64, cryptogram.length - 64);

        //get tag  appended to cryptogram
        byte[] tag = Arrays.copyOfRange(cryptogram, cryptogram.length - 64, cryptogram.length);

        //sponge squeezing of bits
        byte[] keka = FileHash.KMACXOF256(FileHash.concat(rand, pw.getBytes()), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] m = FileHash.KMACXOF256(ke, "".getBytes(), (in.length*  8), "SKE".getBytes());
        m = FileHash.xorBytes(m, in);

        byte[] tPrime = FileHash.KMACXOF256(ka, m, 512, "SKA".getBytes());

        if (Arrays.equals(tag, tPrime)) {
            return m;
        }
        else {
            throw new IllegalArgumentException("Tags didn't match");
        }
    }
    
       
    
    
    /* In this part of the program most functions from here will be getting the user inputs
       *which are used in other functions for inputs and parameters.
    */ 
    public static int getIntInRange(final Scanner userInput, final String prompts,
                                    final int minMenuInput, final int maxMenuInput) {
        int input = getInteger(userInput, prompts);
        while (input < minMenuInput || input > maxMenuInput) {
            System.out.print("Input out of range.\nPlease enter a number that corresponds to a menu prompt.\n");
            input = getInteger(userInput, prompts);
        }
        return input;
    }
    
    public static int getInteger(final Scanner userInput, final String prompts) {
        System.out.println(prompts);
        while (!userInput.hasNextInt()) {
            userInput.next();
            System.out.println("Invalid input. Please enter an integer.");
            System.out.println(prompts);
        }
        return userInput.nextInt();
    }
    
    public static File getInputFile(final Scanner userIn) {
        File theFile;
        boolean pathVerify = false;
        String filePrompt = "Please enter the full path of the file:";
        do {
            System.out.println(filePrompt);
            theFile = new File(userIn.nextLine());
            if (theFile.exists()) {
                pathVerify = true;
            } else {
                System.out.println("ERROR: File doesn't exist.");
            }
        } while (!pathVerify);

        return theFile;
    }
    
    //converting file to string
    public static String fileToString(final File theFile) {
        String theString = null;
        try {
            theString = new String(Files.readAllBytes(theFile.getAbsoluteFile().toPath()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return theString;
    }
    
    // Writes all the required information to an output file.
    private static void writeOutputFile(File outputFile, String contents) {
        Scanner stringScan = new Scanner(contents);
        try {
            FileWriter fw = new FileWriter(outputFile);
            while (stringScan.hasNextLine()) {
                fw.write(stringScan.nextLine());
            }
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
