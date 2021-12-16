package elf;

import java.io.*;
import java.util.*;

public class ELF32File {

    // Смещение таблицы заголовков секций от начала файла в байтах.
    // Если у файла нет таблицы заголовков секций, это поле содержит 0.
    public int e_shoff;
    public String e_shentsize;
    public int e_shnum;
    public String e_shstrndx;
    public Parser parser;
    public Section[] sections;
    public String streamName;
    public Map<Integer, String> strings = new LinkedHashMap<>();
    public List<SymTabString> symbolTable = new ArrayList<>();
    public StringBuilder binaryStrings = new StringBuilder();
    public int textSize;
    public long addr;
    public Map<Long, String> symTableValues = new HashMap<>();



    public ELF32File(BufferedInputStream stream) {
        this.parser = new Parser(stream);
    }

    public void setStreamName(String s) {
        this.streamName = s;
    }

    public void checkHeader() throws IOException {

        String[] ident = parser.nextNHexBytes(16);
        if (!(ident[0].equals("7f") && ident[1].equals("45")
                && ident[2].equals("4c") && ident[3].equals("46"))) {
            throw new InputMismatchException("Invalid magic numbers");
        }

        if (!ident[4].equals("01")) {
            throw new InputMismatchException("Not a 32bit file");
        }

        if (!ident[5].equals("01")) {
            throw new InputMismatchException("Not a littleEndian file");
        }

        parser.skipNBytes(2);

        String e_type = parser.readTwoBytes();
        if (!e_type.equals("00f3")) {
            throw new InputMismatchException("Not a RISC-V file");
        }

        String version = parser.readFourBytes();
        if (Integer.valueOf(version, 16).equals(0)) {
            throw new InputMismatchException("Incorrect version");
        }

        // Пропускаем информация e_entry и про program-header
        parser.skipNBytes(8);

        e_shoff = Integer.valueOf(parser.readFourBytes(), 16);
        if (e_shoff == 0){
            throw new InputMismatchException("elf.Section header doesn't exists");
        }

        parser.skipNBytes(10);
        e_shentsize = parser.readTwoBytes();

        e_shnum = Integer.valueOf(parser.readTwoBytes(), 16);

        e_shstrndx = parser.readTwoBytes();
    }

    public void getSections() throws IOException {
        int bytesToSkip = (e_shoff - 52);
        //Видимо, больше никакая информация, идущая до SectionHeader нам не интересна, поэтому можно ее пропустить
        parser.skipNBytes(bytesToSkip);

        sections = new Section[e_shnum];
        for (int i = 0; i < e_shnum; i++) {
            Section section = new Section();
            section.name = Integer.valueOf(parser.readFourBytes(), 16);
            int sTypeNum = Integer.parseInt(parser.readFourBytes(), 16);
            section.type = SH_TYPE.values()[ sTypeNum <= 18 ? sTypeNum : 19];
            parser.skipNBytes(4);
            section.addr = parser.readFourBytes();
            section.offset = Integer.valueOf(parser.readFourBytes(), 16);
            section.size = Integer.valueOf(parser.readFourBytes(), 16);
            section.link = parser.readFourBytes();
            parser.skipNBytes(8);
            section.entsize = parser.readFourBytes();
            sections[i] = section;
        }
    }

    public void readSectionsNames() throws IOException {
        if (streamName == null) {
            throw new InputMismatchException("Undefined stream name, firstly you have to set it using setStreamName");
        }
        try {
            BufferedInputStream newStream = new BufferedInputStream(new FileInputStream(streamName));

            try {
                ELF32File elfShStrTab = new ELF32File(newStream);
                int shstrStarts = sections[Integer.valueOf(e_shstrndx, 16)].offset;
                elfShStrTab.parser.skipNBytes(shstrStarts);

                int nameOffset = 0;
                for (int i = 0; i < e_shnum; i++) {
                    String name = elfShStrTab.parser.nextNullTermString();
                    if (name == null) {
                        for (int j = 0; j < e_shnum; j++) {
                            if (sections[j].type == SH_TYPE.SHT_NULL) {
                                sections[j].stringName = "0";
                                nameOffset++;
                                break;
                            }
                        }
                    } else {
                        for (int j = 0; j < e_shnum; j++) {
                            if (sections[j].name == nameOffset) {
                                sections[j].stringName = name;
                                nameOffset += name.length() + 1;
                                break;
                            }
                        }
                    }
                }
            } finally {
                newStream.close();
            }
        } catch (IOException e) {
            System.out.println("Something went wrong: " + e);
        }
    }


    public void getStringTableToString() {
        if (streamName == null) {
            throw new InputMismatchException("Undefined stream name, firstly you have to set it using setStreamName");
        }
        try {
            BufferedInputStream newStream = new BufferedInputStream(new FileInputStream(streamName));

            try {
                ELF32File elfStrTab = new ELF32File(newStream);
                int bytesToSkip = 0;
                int strTabSize = 0;
                for (int i = 0; i < e_shnum; i++) {
                    if (sections[i].stringName != null && sections[i].stringName.equals(".strtab")) {
                        bytesToSkip = sections[i].offset;
                        strTabSize = sections[i].size;
                        break;
                    }
                }
                if (bytesToSkip == 0 || strTabSize == 0) {
                    throw new InputMismatchException("No .strtab found or it's empty");
                } else {
                    elfStrTab.parser.skipNBytes(bytesToSkip);
                }
                int bytesRead = 0;

                while (bytesRead < strTabSize) {
                    binaryStrings.append((char) elfStrTab.parser.nextByte());
                    bytesRead++;
                }

            } finally {
                newStream.close();
            }
        } catch (IOException e) {
            System.out.println("Something went wrong: " + e);
        }
    }

    public void getSymTable() throws InputMismatchException{
        getStringTableToString();
        Map<Integer, String> compareType = new HashMap<>(Map.of(0, "NOTYPE", 1, "OBJECT", 2, "FUNC",
                3, "SECTION", 4, "FILE", 5, "COMMON",
                6, "TLS", 10, "LOOS", 12, "HIOS",
                13, "LOPROC"));
        compareType.put(15, "HIPROC");

        Map<Integer, String> compareBinding = new HashMap<>(Map.of(0, "LOCAL", 1, "GLOBAL",
                2, "WEAK", 10, "LOOS", 12, "HIOS", 13, "LOWPROC", 15, "HIPROC"));

        Map<Integer, String> compareVis = new HashMap<>(Map.of(0, "DEFAULT", 1, "INTERNAL",
                2, "HIDDEN", 3, "PROTECTED"));
        if (streamName == null) {
            throw new InputMismatchException("Undefined stream name, firstly you have to set it using setStreamName");
        }
        try {
            BufferedInputStream newStream = new BufferedInputStream(new FileInputStream(streamName));

            try {
                ELF32File elfSymTab = new ELF32File(newStream);
                int bytesToSkip = 0;
                int bytesRead = 0;
                int symTabSize = 0;
                for (int i = 0; i < e_shnum; i++) {
                    if (sections[i].stringName.equals(".symtab")) {
                        bytesToSkip = sections[i].offset;
                        symTabSize = sections[i].size;
                        break;
                    }
                }
                if (bytesToSkip == 0 || symTabSize == 0) {
                    throw new InputMismatchException("No .symtab found or it's empty");
                }
                elfSymTab.parser.skipNBytes(bytesToSkip);
                int counter = 0;
                while (bytesRead < symTabSize) {
                    SymTabString symTab = new SymTabString();
                    symTab.name = Integer.valueOf(elfSymTab.parser.readFourBytes(), 16);
                    bytesRead += 4;
                    if (symTab.name != 0) {
//                        symTab.stringName = strings.get(symTab.name);
                        StringBuilder stringName = new StringBuilder();
                        for (int i = symTab.name; i < binaryStrings.length(); i++) {
                            if (binaryStrings.charAt(i) != 0) {
                                stringName.append(binaryStrings.charAt(i));
                            } else {break;}
                        }
                        symTab.stringName = String.valueOf(stringName);
                    }
                    symTab.value = Long.parseLong(elfSymTab.parser.readFourBytes(), 16);
                    bytesRead += 4;
                    symTab.size = Integer.valueOf(elfSymTab.parser.readFourBytes(), 16);
                    bytesRead += 4;
                    int info = elfSymTab.parser.nextByte();
                    bytesRead++;
                    int bind = info >> 4;
                    symTab.bind = compareBinding.get(bind);
                    int type = info & 0xf;
                    symTab.type = compareType.get(type);
                    int other = elfSymTab.parser.nextByte();
                    bytesRead++;
                    int vis = other & 0x3;
                    symTab.vis = compareVis.get(vis);
                    int index = Integer.valueOf(elfSymTab.parser.readTwoBytes(), 16);
                    if (index == 0) symTab.index = "UNDEF";
                    else if (index == 0xfff1) symTab.index = "ABS";
                    else if (index == 0xff00) symTab.index = "LORESERVE";
                    else if (index == 0xff01) symTab.index = "AFTER";
                    else if (index == 0xff1f) symTab.index = "HIPROC";
                    else if (index == 0xff20) symTab.index = "LOOS";
                    else if (index == 0xff3f) symTab.index = "HIOS";
                    else if (index == 0xfff2) symTab.index = "COMMON";
                    else if (index == 0xffff) symTab.index = "XINDEX";
                    else if (index > 0xff20 && index < 0xff3f) symTab.index = "OSSPEC";
                    else symTab.index = String.valueOf(index);
                    bytesRead += 2;
                    symTab.num = counter;
                    counter++;
                    symbolTable.add(symTab);
                }
            } finally {
                newStream.close();
            }
        } catch (IOException e) {
            System.out.println("Something went wrong: " + e);
        }
    }


    public ELF32File prepareTextSection() throws IOException {
        if (streamName == null) {
            throw new InputMismatchException("Undefined stream name, firstly you have to set it using setStreamName");
        }
        BufferedInputStream newStream = new BufferedInputStream(new FileInputStream(streamName));
        ELF32File elfText = new ELF32File(newStream);
            int bytesToSkip = 0;
            for (int i = 0; i < e_shnum; i++) {
                if (sections[i].stringName != null && sections[i].stringName.equals(".text")) {
                    bytesToSkip = sections[i].offset;
                    textSize = sections[i].size;
                    addr = Long.parseLong(sections[i].addr,16);
                    break;
                }
            }
            if (bytesToSkip == 0 || textSize == 0) {
                throw new InputMismatchException("No .text found or it's empty");
            } else {
                elfText.parser.skipNBytes(bytesToSkip);
            }

        for (SymTabString symTabString : symbolTable) {
            symTableValues.put(symTabString.value, symTabString.stringName);
        }


        return elfText;
    }

    public String make16bit(String str){
        StringBuilder bin = new StringBuilder();
        bin.append("0".repeat(Math.max(0, 16 - str.length())));
        bin.append(str);
        return String.valueOf(bin);
    }

    public String textSectionNext(ELF32File elf) throws IOException {
        String str = elf.parser.readTwoBytes();
        return make16bit(Long.toBinaryString(Long.parseLong(str, 16)));
    }

    public void printSymTab(PrintWriter output) {
        output.printf("%s %-15s %7s %-8s %-8s %-8s %6s %s\n",
                "Symbol", "Value", "Size", "Type", "Bind", "Vis", "Index", "Name");
        for (SymTabString s : symbolTable) {
            output.printf("[%4s] 0x%-15X %5s %-8s %-8s %-8s %6s %s\n",
                    s.num, s.value, s.size, s.type, s.bind, s.vis, s.index, s.stringName);
        }
    }


    public String getSym(long addr) {
        for (SymTabString s : symbolTable) {
            if (s.value == addr && s.type.equals("FUNC")) {
                return s.stringName;
            }
        }
        return null;
    }
}