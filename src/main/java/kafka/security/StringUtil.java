package kafka.security;

import org.jpos.iso.ISOUtil;

import java.util.*;

/**
 * Created by A_Tofigh at 07/16/2024
 */
public class StringUtil {
    public static final String PLATFORM_NEW_LINE =
            System.getProperty("line.separator");
    private static final char MASK_CHAR = '*';
    private static final int DEFAULT_MASK_PREFIX_LENGTH = 4;
    private static final int DEFAULT_MASK_SUFFIX_LENGTH = 4;
    private static final int DEFAULT_MASK_MINIMUM_LENGTH =
            DEFAULT_MASK_PREFIX_LENGTH + DEFAULT_MASK_SUFFIX_LENGTH;
    private static final int PLAIN_TEXT_MAXIMUM_LENGTH = 20;
    private static final int PLAIN_TEXT_MAXIMUM_LENGTH_FACTOR = 4;
    private static final String[] NUMERIC_CHARACTERS = {
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" };
    private static final String[] ALPHA_NUMERIC_CHARACTERS = {
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L",
            "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y",
            "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9" };
    private static final Random RNG = new Random(new Date().getTime());

    public static String mask(
            String textData, int maskMinimumLength,
            int maskPrefixLength, int maskSuffixLength) {
        if (textData == null || textData.isEmpty())
            return textData;
        int inputLength = textData.length();
        StringBuilder stringBuilder;/* = new StringBuilder(textData);*/
        if (inputLength < maskMinimumLength) {
            stringBuilder = new StringBuilder("" + MASK_CHAR);
            /*for (int i = 0; i < inputLength; i++)
                stringBuilder.append(MASK_CHAR);*/
        } else {
            int plainTextMaximumLength =
                    inputLength / PLAIN_TEXT_MAXIMUM_LENGTH_FACTOR
                            < PLAIN_TEXT_MAXIMUM_LENGTH
                            ? inputLength / PLAIN_TEXT_MAXIMUM_LENGTH_FACTOR
                            : PLAIN_TEXT_MAXIMUM_LENGTH;
            int longDataFactor =
                    inputLength / (maskPrefixLength + maskSuffixLength);
            int maskStartIndex = longDataFactor * maskPrefixLength / 2;
            int maskEndIndex = longDataFactor * maskSuffixLength / 2;
            maskStartIndex = maskStartIndex < plainTextMaximumLength
                    ? maskStartIndex : plainTextMaximumLength;
            maskEndIndex = inputLength - maskEndIndex > plainTextMaximumLength
                    ? inputLength - maskEndIndex : plainTextMaximumLength;
            stringBuilder =
                    new StringBuilder(maskStartIndex + 1 + maskEndIndex);
            stringBuilder
                    .append(textData.substring(0, maskStartIndex))
                    .append(MASK_CHAR)
                    .append(textData.substring(maskEndIndex, inputLength));
            /*for (int i = maskStartIndex; i < maskEndIndex; i++)
                stringBuilder.setCharAt(i, MASK_CHAR);*/
        }
        return stringBuilder.toString();
    }

    public static String mask(String textData) {
        return mask(textData, DEFAULT_MASK_MINIMUM_LENGTH,
                DEFAULT_MASK_PREFIX_LENGTH, DEFAULT_MASK_SUFFIX_LENGTH);
    }

    public static String maskShortItem(String textData) {
        return mask(textData, 0, 1, 1);
    }

    public static String maskCellphoneNo(String cellphoneNo) {
        if (cellphoneNo == null || cellphoneNo.isEmpty())
            return cellphoneNo;
        if (cellphoneNo.length() > 9)
            cellphoneNo = cellphoneNo.substring(
                    cellphoneNo.length() - 10, cellphoneNo.length());
        else
            cellphoneNo = fixWidthSpacePad(cellphoneNo, 10);
        return cellphoneNo.substring(0, 3) + "*" + cellphoneNo.substring(6, 10);
    }

    private static String maskPanOrTrack2(String panOrTrack2, int plainLength) {
        if (panOrTrack2 == null || panOrTrack2.isEmpty())
            return panOrTrack2;
        panOrTrack2 = panOrTrack2.length() < 16
                ? fixWidthSpacePad(panOrTrack2, 16) : panOrTrack2;
        String panPart;
        String maskedPan;
        boolean pan = panOrTrack2.length() == 16 || panOrTrack2.length() == 19;
        int equalSignIndex = panOrTrack2.indexOf("=");
        boolean equalSignAbsent = equalSignIndex == -1;
        equalSignIndex =
                equalSignAbsent ? panOrTrack2.length() : equalSignIndex;
        panPart = pan ? panOrTrack2 : panOrTrack2.substring(0, equalSignIndex);
        maskedPan = panPart.substring(0, plainLength) + "*"
                + panPart.substring(12, panPart.length());
        equalSignIndex =
                equalSignAbsent ? panOrTrack2.length() - 5 : equalSignIndex;
        return pan ? maskedPan : maskedPan + panOrTrack2.substring(
                equalSignIndex, equalSignIndex + 5)
                + (equalSignAbsent ? "" : "*");
    }

    public static String fixWidth(
            String text, int desiredLen, String padder, boolean leftPad) {
        if (text == null)
            text = "";
        if (text.length() >= desiredLen) {
            // Consider important part of data when stripping away some of chars
            return leftPad
                    ? text.substring(text.length() - desiredLen, text.length())
                    : text.substring(0, desiredLen);
        }
        StringBuilder stringBuilder = new StringBuilder(desiredLen);
        int fillLen = desiredLen - text.length();
        if (!leftPad)
            stringBuilder.append(text);
        while (fillLen-- > 0)
            stringBuilder.append(padder);
        if (leftPad)
            stringBuilder.append(text);
        return stringBuilder.toString();
    }

    public static String fixWidth(
            String text, int desiredLen, char paddingChar, boolean leftPad) {
        return fixWidth(text, desiredLen, "" + paddingChar, leftPad);
    }

    public static String fixWidthLeftPad(
            String text, int desiredLen, char paddingChar) {
        return fixWidth(text, desiredLen, paddingChar, true);
    }

    public static String fixWidthRightPad(
            String text, int desiredLen, char paddingChar) {
        return fixWidth(text, desiredLen, paddingChar, false);
    }

    public static String fixWidthZeroPad(String text, int desiredLen) {
        return fixWidth(text, desiredLen, '0', true);
    }

    public static String fixWidthZeroPad(Long number, int desiredLen) {
        return fixWidth(number == null ? null : String.valueOf(number),
                desiredLen, '0', true);
    }

    public static String fixWidthZeroPad(Number number, int desiredLen) {
        return fixWidth(number == null ? null : String.valueOf(number),
                desiredLen, '0', true);
    }

    public static String fixWidthSpacePad(String text, int desiredLen) {
        return fixWidth(text, desiredLen, ' ', false);
    }

    public static String replaceNonDigitsWithZero(String str) {
        StringBuilder transformedString = new StringBuilder();
        for (char c : str.toCharArray()) {
            if (Character.isDigit(c))
                transformedString.append(c);
            else
                transformedString.append('0');
        }
        return transformedString.toString();
    }

    public static String trim(String str) {
        //return trim(str, ' ');
        if (str == null)
            return null;
        return str.trim();
    }

    public static String trim(String str, char ch) {
        String result = ISOUtil.unPadLeft(str, ch);
        result = ISOUtil.unPadRight(result, ch);
        // nullify the strange effect of jPOS unPadRight()
        if (result.length() == 1 && result.charAt(0) == ch)
            return "";
        return result;
    }

    public static String trimLeft(String str) {
        return trimLeft(str, ' ');
    }

    public static String trimLeft(String str, char ch) {
        String result = ISOUtil.unPadLeft(str, ch);
        // nullify the strange effect of jPOS unPadRight()
        if (result.length() == 1 && result.charAt(0) == ch)
            return "";
        return result;
    }

    public static String trimRight(String str) {
        return ISOUtil.unPadRight(str, ' ');
    }

    public static String trimRight(String str, char ch) {
        String result = ISOUtil.unPadRight(str, ch);
        // nullify the strange effect of jPOS unPadRight()
        if (result.length() == 1 && result.charAt(0) == ch)
            return "";
        return result;
    }

    public static String trimLeadingZeroes(String numberString) {
        return ISOUtil.unPadLeft(numberString, '0');
    }

    public static String trimTrailingZeroes(String numberString) {
        return ISOUtil.unPadRight(numberString, '0');
    }

    public static String toHex(byte aByte) {
        char highNibble = Character.forDigit((aByte >> 4) & 0x0F, 16);
        char lowNibble = Character.forDigit(aByte & 0x0F, 16);
        return "" + highNibble + lowNibble;
    }

    public static String toHex(int anInt) {
        return Integer.toHexString(anInt);
    }

    public static String toHex0x(byte aByte) {
        return "0x" + toHex(aByte);
    }

    public static String toHex0x(int anInt) {
        return "0x" + toHex(anInt);
    }

    public static String asciiHexFromHexDump(String hexDump) throws Exception {
        if (hexDump.length() % 2 != 0)
            throw new Exception("Hex dump length should be even");
        StringBuilder ascii = new StringBuilder();
        for (int i = 0; i < hexDump.length(); i += 2) {
            ascii.append(Character.forDigit(
                    Integer.parseInt(hexDump.substring(i, i + 2)), 16));
        }
        return ascii.toString();
    }

    public static String generateRandomNumeric(int length) {
        //return ("" + RNG.nextLong()).substring(0, length);
        StringBuilder randomNumericStringBuilder = new StringBuilder();
        for (int i = 0; i < length; i++)
            randomNumericStringBuilder.append(NUMERIC_CHARACTERS[
                    RNG.nextInt(NUMERIC_CHARACTERS.length)]);
        return randomNumericStringBuilder.toString();
    }

    public static String generateRandomAlphaNumeric(int length) {
        StringBuilder randomNumericStringBuilder = new StringBuilder();
        for (int i = 0; i < length; i++)
            randomNumericStringBuilder.append(ALPHA_NUMERIC_CHARACTERS[
                    RNG.nextInt(ALPHA_NUMERIC_CHARACTERS.length)]);
        return randomNumericStringBuilder.toString();
    }

    public static String getOrdinalSuffix(int number) {
        return number > 10 && number <= 20 ? "th"
                : number % 10 == 1 ? "st"
                : number % 10 == 2 ? "nd"
                : number % 10 == 3 ? "rd"
                : "th";
    }
}
