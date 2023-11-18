
/*
    *This class generates all the applicable methods for doing cryptographic encryption and decryption
    *computing the plain cryptographic hash form of a file and intput text 
    *computing the authedication tag of a given file and also that of a given text using a given passphrase
    *Encryption of a a given data file symmetrically under a given passphrase.
    *Decryption of a a given symmetric cryptogram under a given passphrase
    
    *Most important it is where the cSHAKE256() AND KMAXOF256() methods are declared
    *There actual implementations are made in the Main.java class

*/

import java.math.BigInteger;
import java.util.Arrays;


public class FileHash {
    //definition of constants which are 24
     private static final long[] keccakfRndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
    
    
    private static final int[] keccakfPilane = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };
     
     //offsets for the roh function.
     
    private static final int[] keccakfRotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    
    //performing keccak permutations
    //permutation function
     private static long[] keccak(long[] stateIn, int bitLen, int rounds) {
        long[] stateOut = stateIn;
        int l = floorLog(bitLen/25);
        for (int i = 12 + 2*l - rounds; i < 12 + 2*l; i++) {
            stateOut = iota(chi(rhoPhi(theta(stateOut))), i); // sec 3.3 FIPS 202
        }
        return stateOut;
    }
    //stateIn is the input state
    //stateout is the output state
    private static long[] theta(long[] stateIn) {
        long[] stateOut = new long[25];
        long[] C = new long[5];

        for (int i = 0; i < 5; i++) {
            C[i] = stateIn[i] ^ stateIn[i + 5] ^ stateIn[i + 10] ^ stateIn[i + 15] ^ stateIn[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            long d = C[(i+4) % 5] ^ rotateLane64(C[(i+1) % 5], 1);

            for (int j = 0; j < 5; j++) {
                stateOut[i + 5*j] = stateIn[i + 5*j] ^ d;
            }
        }

        return stateOut;
    }
    //rho and phi function
    private static long[] rhoPhi(long[] stateIn) {
        long[] stateOut = new long[25];
        stateOut[0] = stateIn[0]; // copying first value
        long t = stateIn[1], temp;
        int ind;
        for (int i = 0; i < 24; i++) {
            ind = keccakfPilane[i];
            temp = stateIn[ind];
            stateOut[ind] = rotateLane64(t, keccakfRotc[i]);
            t = temp;
        }
        return stateOut;
    }
    
    /*  The chi function
        returns the state after applying the chi function
    */
     private static long[] chi(long[] stateIn) {
        long[] stateOut = new long[25];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                long tmp = ~stateIn[(i+1) % 5 + 5*j] & stateIn[(i+2) % 5 + 5*j];
                stateOut[i + 5*j] = stateIn[i + 5*j] ^ tmp;
            }
        }
        return stateOut;
    }
    
    /*
        Applies the round constant to the word at stateIn[0].
    */
    private static long[] iota(long[] stateIn, int round) {
        stateIn[0] ^= keccakfRndc[round];
        return stateIn;
    }
    
    /*
        the sponge function for sponge functionality
    */
     private static byte[] sponge(byte[] in, int bitLen, int cap) {
        int rate = 1600 - cap;
        byte[] padded = in.length % (rate / 8) == 0 ? in : padTenOne(rate, in); // one bit of padding already appended
        long[][] states = byteArrayToStates(padded, cap);
        long[] stcml = new long[25];
        for (long[] st : states) {
            stcml = keccak(xorStates(stcml, st), 1600, 24); // Keccak[c] restricted to bitLen 1600
        }

        long[] out = {};
        int offset = 0;
        do {
            out = Arrays.copyOf(out, offset + rate / 64);
            System.arraycopy(stcml, 0, out, offset, rate / 64);
            offset += rate / 64;
            stcml = keccak(stcml, 1600, 24);
        } while (out.length * 64 < bitLen);

        return stateToByteArray(out, bitLen);
    }
     
    private static byte[] padTenOne(int rate, byte[] in) {
        int bytesToPad = (rate / 8) - in.length % (rate / 8);
        byte[] padded = new byte[in.length + bytesToPad];
        for (int i = 0; i < in.length + bytesToPad; i++) {
            if (i < in.length) padded[i] = in[i];
            else if (i==in.length + bytesToPad - 1) padded[i] = (byte) 0x80;
            else padded[i] = 0;
        }

        return padded;
    }
    
    /*
        ========================== KMACXOF256 FUNCTIONALITY======================================
        the function has to Produce a variable length message digest based on the keccak-f permations
    */
    public static byte[] SHAKE256(byte[] in, int bitLen) {
        byte[] uin = Arrays.copyOf(in, in.length + 1);
        int bytesToPad = 136 - in.length % (136); // rate is 136 bytes
        uin[in.length] = bytesToPad == 1 ? (byte) 0x9f : 0x1f; // pad with suffix defined in FIPS 202 sec. 6.2
        return sponge(uin, bitLen, 512);
    }
    
    /*
        The cSHAKE256 function
        implements sponge function
        then concatenates bits
    */
    public static byte[] cSHAKE256(byte[] in, int bitLength, byte[] functionName, byte[] customStr) {
        if (functionName.length == 0 && customStr.length == 0) return SHAKE256(in, bitLength);

        byte[] fin = concat(encodeString(functionName), encodeString(customStr));
        fin = concat(bytePad(fin, 136), in);
        fin = concat(fin, new byte[] {0x04});

        return sponge(fin, bitLength, 512);
    }
    
    /*
        the KMACXOF256 FUNCTION
        made for producing the plain cryptographic hash text
    */
    public static byte[] KMACXOF256(byte[] key, byte[] in, int bitLength, byte[] customString) {

        byte[] newX = concat(concat(bytePad(encodeString(key),136), in), rightEncode(BigInteger.ZERO));
        return cSHAKE256(newX, bitLength, "KMAC".getBytes(), customString);
    }
    
    /*
        Right encode method/ for rightEncode functionality
        performs encoding of bits X onto the right side of the code
    */
    private static byte[] rightEncode(BigInteger x) {
        //establishing the validity of x whi should be 0 <= x < 2^2040
        assert 0 < x.compareTo(new BigInteger(String.valueOf(Math.pow(2, 2040))));

        int n = 1;
        
        while (x.compareTo(new BigInteger(String.valueOf((int)Math.pow(2, (8*n))))) != -1) {
            n++;
        }
        
        byte[] xBytes = x.toByteArray();
        
        // handle exception where first byte is zero
        if ((xBytes[0] == 0) && (xBytes.length > 1)) {
            byte[] temp = new byte[xBytes.length - 1];
            System.arraycopy(xBytes, 1, temp, 0, xBytes.length - 1);
            xBytes = temp;
        }
        
        byte[] output = new byte[xBytes.length + 1];
        
        for (int i = 0; i < xBytes.length; i++) {
            output[xBytes.length - (i+1)] = xBytes[i];
        }
        
        output[0] =(byte)n;
        return output;
    }
    
    /*
        left encode method
        it encodes the existing bits onto the left
    */
    private static byte[] leftEncode(BigInteger x) {
        //Establishing the Validity of X which should be 0 <= x < 2^2040
        assert 0 < x.compareTo(new BigInteger(String.valueOf(Math.pow(2, 2040))));

        int n = 1;

        while (x.compareTo(new BigInteger(String.valueOf((int)Math.pow(2, (8*n))))) != -1) {
            n++;
        }
       
        // representation of x in a bytearray
        byte[] xBytes = x.toByteArray();
        
        if ((xBytes[0] == 0) && (xBytes.length > 1)) {
            byte[] temp = new byte[xBytes.length - 1];
            System.arraycopy(xBytes, 1, temp, 0, xBytes.length - 1);
            xBytes = temp;
        }
        
        byte[] output = new byte[xBytes.length + 1];
        for (int i = 0; i < xBytes.length; i++) {
            //xBytes[i] = reverseBitsByte(xBytes[i]);
            output[xBytes.length - (i)] = xBytes[i];
        }
        
        output[0] =(byte)n;
        return output;
    }
    
    //encoding string
    private static byte[] encodeString(byte[] S) {
        if (S == null || S.length == 0) {
            return leftEncode(BigInteger.ZERO);
        } else {
            
            return concat(leftEncode(new BigInteger(String.valueOf(S.length << 3))), S);
        }
    }
    
    /*
        bytepad functionality to do padding
    */
    private static byte[] bytePad(byte[] X, int w) {

        //validating the condition that w>0
        assert w > 0;
        
        byte[] wEnc = leftEncode(BigInteger.valueOf(w));
        
        byte[] z = new byte[w * ((wEnc.length + X.length + w - 1)/w)];

        /* 
            Concatenates wEnc and X into z (z = wEnc || X)
            copies wEnc into z from z[0] to z[wEnc.length]
        */
        System.arraycopy(wEnc, 0, z, 0, wEnc.length);
        // copies X into z frm z[wEnc.length] till all X copied into z
        System.arraycopy(X,0,z,wEnc.length, X.length);

        
        for (int i = wEnc.length + X.length; i < z.length; i++) {
            z[i] = (byte) 0;
        }

        return z;
    }
    
    /*
        rotateLane function to perform bit rotation on given lane
    */
    private static long rotateLane64(long x, int y) {
        return (x << (y%64)) | (x >>> (64 - (y%64)));
    }
    
    //find floorLog 
    private static int floorLog(int n) {
        if (n < 0) throw new IllegalArgumentException("Log is undefined for negative numbers.");
        int exp = -1;
        while (n > 0) {
            n = n>>>1;
            exp++;
        }
        return exp;
    }
    
    /*
        find xor states of bits
    */
    private static long[] xorStates(long[] s1, long[] s2) {
        long[] out = new long[25];
        for (int i = 0; i < s1.length; i++) {
            out[i] = s1[i] ^ s2[i];
        }
        return out;
    }
    
    /*
        convert to array of bytes
    */
    private static byte[] stateToByteArray(long[] state, int bitLen) {
        if (state.length*64 < bitLen) throw new IllegalArgumentException("State is of insufficient length to produced desired bit length.");
        byte[] out = new byte[bitLen/8];
        int wrdInd = 0;
        while (wrdInd*64 < bitLen) {
            long word = state[wrdInd++];
            int fill = wrdInd*64 > bitLen ? (bitLen - (wrdInd - 1) * 64) / 8 : 8;
            for (int b = 0; b < fill; b++) {
                byte ubt = (byte) (word>>>(8*b) & 0xFF);
                out[(wrdInd - 1)*8 + b] = ubt;
            }
        }

        return out;
    }
    
    //function to convert byte array series to state array series
    private static long[][] byteArrayToStates(byte[] in, int cap) {
        long[][] states = new long[(in.length*8)/(1600-cap)][25];
        int offset = 0;
        for (int i = 0; i < states.length; i++) {
            long[] state = new long[25];
            for (int j = 0; j < (1600-cap)/64; j++) {
                long word = bytesToWord(offset, in);
                state[j] = word;
                offset += 8;
            }
           
            states[i] = state;
        }
        return states;
    }
    /*
    convert byte to 64bit word
        Converts the resultant byte to 64bits
    */
    private static long bytesToWord(int offset, byte[] in) {
        if (in.length < offset+8) throw new IllegalArgumentException("Byte range unreachable, index out of range.");
        
        long word = 0L;
        for (int i = 0; i < 8; i++) {
            word += (((long)in[offset + i]) & 0xff)<<(8*i);
        }
        return word;
    }
    
    public static byte[] xorBytes(byte[] b1, byte[] b2) {
        byte[] out = new byte[b1.length];
        for (int i = 0; i < b1.length; i++) {
            out[i] = (byte) (b1[i] ^ b2[i]);
        }
        return out;
    }
    
    /*
        concatenate two bytes in their order
        joins the bytes together to be come one
    */
    public static byte[] concat(byte[] b1, byte[] b2) {
        byte[] z = new byte[b1.length + b2.length];
        System.arraycopy(b1,0,z,0,b1.length);
        System.arraycopy(b2,0,z,b1.length,b2.length);
        return z;
    }
    
    //convert byte array into hexadecimal representation
    public static String bytesToHexString(byte[] b)  {
        int space = 0;

        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if(space == 1) {
                hex.append(" ");
                space = 0;
            }

            hex.append(String.format("%02X", b[i]));
            space++;
        }
        return hex.toString();
    }
    
    /*
        convert string to byte array
        converts the string generated into a byte array
    */
    public static byte[] hexStringToBytes(String s) {
        s = s.replaceAll("\\s", "");
        byte[] val = new byte[s.length()/2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(s.substring(index,index + 2), 16);
            val[i] = (byte) j;
        }
        return val;
    }   
    
}
