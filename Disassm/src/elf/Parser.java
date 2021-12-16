package elf;

import java.io.BufferedInputStream;
import java.io.IOException;

public class Parser {
    BufferedInputStream stream;
    int curOffset = 0;

    public Parser(BufferedInputStream stream) {
        this.stream = stream;
    }

    public int nextByte() throws IOException {
        curOffset++;
        return stream.read();
    }

    public String nextNullTermString() throws IOException {
        int b = 0;
        StringBuilder sb = new StringBuilder();
        do {
            b = stream.read();
            curOffset++;
            sb.append((char) b);
        } while (b != 0);
        return sb.length() > 1 ? String.valueOf(sb.substring(0, sb.length() - 1)) : null;
    } // Так можно прочитать названия секция в shstrtab

    public void skipNBytes(int n) throws IOException {
        if (n != 0) {
            byte[] toSkip = stream.readNBytes(n);
            curOffset += n;
        }
    }

    public String[] nextNHexBytes(int n) throws IOException {
        String[] hexBytes = new String[n];
        for (int i = 0; i < n; i++) {
            int hexByte = stream.read();
            curOffset++;
            hexBytes[i] = String.format("%2s", Integer.toHexString(hexByte & 0xFF)).replace(' ', '0');
        }
        return hexBytes;
    }

    // Читаем байты с учетом little-endian
    public String readTwoBytes() throws IOException {
        int b1 = stream.read();
        int b2 = stream.read();
        curOffset += 2;
        return String.format("%2s", Integer.toHexString(b2 & 0xFF)).replace(' ', '0') +
                String.format("%2s", Integer.toHexString(b1 & 0xFF)).replace(' ', '0');
    }

    public String readFourBytes() throws IOException {
        int b1 = stream.read();
        int b2 = stream.read();
        int b3 = stream.read();
        int b4 = stream.read();
        curOffset += 4;
        return String.format("%2s", Integer.toHexString(b4 & 0xFF)).replace(' ', '0') +
                String.format("%2s", Integer.toHexString(b3 & 0xFF)).replace(' ', '0') +
                String.format("%2s", Integer.toHexString(b2 & 0xFF)).replace(' ', '0') +
                String.format("%2s", Integer.toHexString(b1 & 0xFF)).replace(' ', '0');
    }
}
