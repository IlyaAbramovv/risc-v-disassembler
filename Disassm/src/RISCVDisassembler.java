import elf.ELF32File;

import java.io.*;
import java.util.HashSet;
import java.util.Set;

public class RISCVDisassembler {
    public ELF32File elf;
    public long addr;
    public PrintWriter output;
    int decimalWord;
    int rd;
    int funct3;
    int rs1;
    int rs2;
    int imm110;
    int funct7;
    int opcode;
    Set<Long> unknownMarks = new HashSet<>();
    String operation;
    int imm;


    public RISCVDisassembler(PrintWriter output) {
        this.output = output;
    }

    public void disassemble(String word) {
        String mark;
        mark = elf.getSym(addr);
        if (mark == null && unknownMarks.contains(addr)) {
            mark = String.format("LOC_%05x:", addr);
        } else if (mark == null){
            mark = "";
        } else mark += ":";
        decimalWord = (int) Long.parseLong(word, 2);

        if (word.length() == 32) { // Это не RVC
            getUsefulThingsFromWord();

            if (opcode == 0b0110011) { //R-type
                disR(word);
                output.printf("%08x %10s %s %s, %s, %s\n",
                        addr, mark, operation, getRegister(rd), getRegister(rs1), getRegister(rs2));
            } else if (opcode == 0b0100011) { //S-type
                disS();
                output.printf("%08x %10s %s %s, %s(%s)\n", addr, mark, operation, getRegister(rs2), imm, getRegister(rs1));
            } else if (opcode == 0b0110111) { //U-type, lui
                output.printf("%08x %10s %s %s, %s\n", addr, mark, "lui", getRegister(rd),
                        Integer.toUnsignedString((decimalWord >>> 12) << 12));
//            output.printf("%6s %s, %s", "lui", getRegister(rd),
//                    Integer.toUnsignedString((decimalWord >>> 12) << 12));
            } else if (opcode == 0b0010111) { //U-type, auipc
                output.printf("%08x %10s %s %s, %s\n", addr, mark, "auipc", getRegister(rd),
                        Integer.toUnsignedString((decimalWord >>> 12) << 12));
//            output.printf("%6s %s, %s", "auipc", getRegister(rd),
//                    Integer.toUnsignedString((decimalWord >>> 12) << 12));
            } else if (opcode == 0b1101111) { //J-type, jal
                disJ(word);
                String m = elf.getSym(addr + imm) != null ?
                        elf.getSym(addr + imm) : String.format("LOC_%05x", addr + imm);
                output.printf("%08x %10s %s %s, %s #0x%05x %s\n", addr, mark, "jal", getRegister(rd), imm, addr + imm, m);
            } else if (opcode == 0b1100111) { //I-type, jalr
                int imm_i = decimalWord >> 20;
                output.printf("%08x %10s %s %s, %s(%s)\n", addr, mark, "jalr", getRegister(rd), imm_i, getRegister(rs1));
            } else if (opcode == 0b0000011) { //I-type, load
                disIload();
                int imm_i = decimalWord >> 20;
                output.printf("%08x %10s %s %s, %s(%s)\n", addr, mark, operation, getRegister(rd), imm_i, getRegister(rs1));
            } else if (opcode == 0b0010011) { //I-type, arithmetic or shifts
                disIarithm(word);
                int imm_i;
                if (operation.equals("slli") || operation.equals("srli") || operation.equals("srai")) {
                    imm_i = (decimalWord << 7) >>> 27; //Тут imm_i означает shamt
                } else {
                    imm_i = decimalWord >> 20;
                }
                output.printf("%08x %10s %s %s, %s, %s\n", addr, mark, operation, getRegister(rd), getRegister(rs1), imm_i);
            } else if (opcode == 0b1100011) { //B-type
                disB();
                StringBuilder sb = new StringBuilder();
                sb.append(String.valueOf(word.charAt(0)).repeat(20)).append(word.charAt(24))
                        .append(word, 1, 7).append(word, 20, 25).append("0");
                int imm_b = (int) Long.parseLong(String.valueOf(sb), 2);
                String m = elf.getSym(addr + imm_b) != null ?
                        elf.getSym(addr + imm_b) : String.format("LOC_%05x", addr + imm_b);
                output.printf("%08x %10s %s %s, %s, %s #0x%05x %s\n",
                        addr, mark, operation, getRegister(rs1), getRegister(rs2), imm_b, addr + imm_b, m);
            } else if (opcode == 0b1110011) { //System cmds
                if (funct3 == 0b000 && word.charAt(11) == '0') { //ecall
                    output.printf("%08x %10s %s\n", addr, mark, "ecall");
                } else if (funct3 == 0b000 && word.charAt(11) == '1') { //ebreak
                    output.printf("%08x %10s %s\n", addr, mark, "ebreak");
                } else { //csr
                    disCSR();
                    output.printf("%08x %10s %s %s, %s, %s\n",
                            addr, mark, operation, getRegister(rd), imm110, getRegister(rs1));
                }
            } else {
                output.printf("%08x %10s\n", addr, "unknown_command");
            }
        } else { // RVC 
            opcode = decimalWord & ((1 << 2) - 1);
            funct3 = decimalWord >>> 13;
            short imm;
            int uimm;

            if (opcode == 0b00) {
//                int rd = (decimalWord << 27) >>> 29;
//                rs1 = (decimalWord << 19) >>> 26;
                int rd = Integer.parseInt(word.substring(11, 14),2);
                rs1 = Integer.parseInt(word.substring(6, 9), 2);

                int intUimm = Integer.parseInt(
                        word.charAt(10) + word.substring(3, 6) + word.charAt(9) + "00", 2);
                switch (funct3){
                    case (0b000): //c.addi4spn
                        int nzuimm = Integer.parseInt(word.substring(5, 9) + word.substring(3,5) +
                                word.charAt(10) + word.charAt(9) + "00", 2);
                        output.printf("%08x %10s %s %s, %s, %s\n",
                                addr, mark, "c.addi4spn", getABIRegister(rd), "sp", nzuimm);
                        break;
                    case (0b010): //c.lw
                        uimm = intUimm;
                        output.printf("%08x %10s %s %s, %s(%s)\n",
                                addr, mark, "c.lw", getABIRegister(rd), uimm, getABIRegister(rs1));
                        break;
                    case (0b110): //c.sw
                        uimm = intUimm;
                        output.printf("%08x %10s %s %s, %s(%s)\n",
                                addr, mark, "c.sw", getABIRegister(rd), uimm, getABIRegister(rs1));
                        break;
                    default:
                        output.printf("%08x %10s\n", addr, "unknown_command");
                        break;
                }
            } else if (opcode == 0b01) {
                int intImm = Integer.parseInt(String.valueOf(word.charAt(3)).repeat(10) +
                        word.charAt(3) + word.substring(9, 14), 2);
                switch (funct3) {
                    case (0b000):
                        if (decimalWord == 1) { //c.nop
                            output.printf("%08x %10s %s\n",
                                    addr, mark, "c.nop");
                            break;
                        } else { //c.addi
                            short nzuimm = (short) intImm;
                            output.printf("%08x %10s %s %s, %s\n",
                                    addr, mark, "c.addi", getRegister(word.substring(4, 9)), nzuimm);
                            break;
                        }
                    case (0b001): //c.jal
                        imm = getImmForRVCJumps(word);
                        String m = elf.getSym(addr + imm) != null ?
                                elf.getSym(addr + imm) : String.format("LOC_%05x", addr + imm);
                        output.printf("%08x %10s %s %s #0x%05x %s\n",
                                addr, mark, "c.jal", imm, addr + imm, m);
                        break;
                    case (0b010): //c.li
                        imm = (short) intImm;
                        output.printf("%08x %10s %s %s, %s\n",
                                addr, mark, "c.li", getRegister(word.substring(4, 9)), imm);
                        break;
                    case (0b011): //c.addi16sp
                        if (word.startsWith("00010", 4)) { //c.addi16sp
                            imm = (short) Integer.parseInt(String.valueOf(word.charAt(3)).repeat(6) +
                                    word.charAt(3) + word.substring(11, 13) + word.charAt(10) + word.charAt(13) +
                                    word.charAt(9) + "0000", 2);
                            output.printf("%08x %10s %s %s, %s\n",
                                    addr, mark, "c.addi16sp", "sp", imm);
                            break;
                        } else { //c.lui
                            int luiImm = Integer.parseInt(String.valueOf(word.charAt(3)).repeat(14) +
                                    word.charAt(3) + word.substring(9, 14), 2);
                            output.printf("%08x %10s %s %s, %s\n",
                                    addr, mark, "c.lui", getRegister(word.substring(4, 9)), luiImm);
                            break;
                        }
                    case (0b100):
                        String operation = disRVCArithm(word);
                        output.printf("%08x %10s %s %s, %s\n", addr, mark, operation,
                                getABIRegister(word.substring(6, 9)), getABIRegister(word.substring(11, 14)));
                        break;
                    case (0b101): //c.j
                        imm = getImmForRVCJumps(word);
                        m = elf.getSym(addr + imm) != null ?
                                elf.getSym(addr + imm) : String.format("LOC_%05x", addr + imm);
                        output.printf("%08x %10s %s %s #0x%05x %s\n",
                                addr, mark, "c.j", imm, addr + imm, m);
                        break;
                    case (0b110): //c.beqz, c.bnez
                    case (0b111):
                        imm = (short) Integer.parseInt(String.valueOf(word.charAt(3)).repeat(7) +
                                word.charAt(3) + word.substring(9, 11) + word.charAt(13) + word.substring(4, 6) +
                                word.substring(11, 13) + "0", 2);
                        m = elf.getSym(addr + imm) != null ?
                                elf.getSym(addr + imm) : String.format("LOC_%05x", addr + imm);
                        output.printf("%08x %10s %s %s %s #0x%05x %s\n",
                                addr, mark, word.startsWith("110") ? "c.beqz" : "c.bnez",
                                getABIRegister(word.substring(6, 9)), imm, addr + imm, m);
                        break;
                    default:
                        output.printf("%08x %10s\n", addr, "unknown_command");
                        break;
                }
            } else if (opcode == 0b10) {
                switch (funct3) {
                    case (0b000): //c.slli
                        uimm = Integer.parseInt(word.charAt(3) + word.substring(9, 14));
                        output.printf("%08x %10s %s %s, %s\n",
                                addr, mark, "c.slli", getRegister(word.substring(4, 9)), uimm);
                        break;
                    case (0b010): //c.lwsp
                        uimm = Integer.parseInt(word.substring(12, 14) + word.charAt(3) +
                                word.substring(9, 12), 2);
                        output.printf("%08x %10s %s %s, %s(%s)\n", addr, mark, "c.lwsp",
                                getRegister(word.substring(4, 9)), uimm, "sp");
                        break;
                    case (0b100):
                        if (word.charAt(3) == '0' && word.substring(9, 14).equals("00000")) { //c.jr
                            output.printf("%08x %10s %s %s\n", addr, mark, "c.jr", getRegister(word.substring(4, 9)));
                            break;
                        } else if (word.charAt(3) == '0') { //c.mv
                            output.printf("%08x %10s %s %s, %s\n", addr, mark, "c.mv",
                                    getRegister(word.substring(4, 9)), getRegister(word.substring(9, 14)));
                            break;
                        } else if (word.charAt(3) == '1' && word.substring(4, 9).equals("00000") &&
                                    word.substring(9, 14).equals("00000")) { //c.ebreak
                            output.printf("%08x %10s %s\n", addr, mark, "c.ebreak");
                            break;
                        } else if (word.charAt(3) == '1' && word.substring(9, 14).equals("00000")) { //c.jalr
                            output.printf("%08x %10s %s %s\n", addr, mark, "c.jalr", getRegister(word.substring(4, 9)));
                            break;
                        } else { //c.add
                            output.printf("%08x %10s %s %s, %s\n", addr, mark, "c.add",
                                    getRegister(word.substring(4, 9)), getRegister(word.substring(9, 14)));
                            break;
                        }
                    case (0b110): //c.swsp
                        uimm = Integer.parseInt(word.substring(7, 9) + word.substring(3, 7) + "00", 2);
                        output.printf("%08x %10s %s %s, %s(%s)\n", addr, mark, "c.swsp",
                                getRegister(word.substring(9, 14)), uimm, "sp");
                        break;
                    default:
                        output.printf("%08x %10s\n", addr, "unknown_command");
                }
            }
        }
    }

    private void getUsefulThingsFromWord() {
        opcode = decimalWord & ((1 << 7) - 1);
        rd = decimalWord >> 7 & ((1 << 5) - 1);
        funct3 = decimalWord >> 12 & ((1 << 3) - 1);
        rs1 = decimalWord >> 15 & ((1 << 5) - 1);
        rs2 = decimalWord >> 20 & ((1 << 5) - 1);
        imm110 = decimalWord >> 20 & ((1 << 12) - 1);
        funct7 = decimalWord >> 25;
    }

    private short getImmForRVCJumps(String word) {
        short imm;
        imm = (short) Integer.parseInt(
                String.valueOf(word.charAt(3)).repeat(4) + word.charAt(3) + word.charAt(7) +
                        word.substring(5, 7) + word.charAt(9) + word.charAt(13) +
                        word.charAt(4) + word.substring(10, 13) + "0", 2);
        return imm;
    }

    private String disRVCArithm(String word) {
        int code11_10 = Integer.parseInt(word.substring(4, 6), 2);
        int code6_5 = Integer.parseInt(word.substring(9, 11), 2);
        if (code11_10 == 0b00) return "c.srli";
        else if (code11_10 == 0b01) return "c.srai";
        else if (code11_10 == 0b10) return "c.endi";
        else if (code11_10 == 0b11) {
            switch (code6_5) {
                case (0b00):
                    return "c.sub";
                case (0b01):
                    return "c.xor";
                case (0b10):
                    return "c.or";
                case (0b11):
                    return "c.and";
                default:
                    return "unknown_command";
            }
        } else return "unknown_command";
    }

    private String getABIRegister(int rd) {
        String[] regs = new String[]{"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5"};
        return regs[rd];
    }

    private String getABIRegister(String rd) {
        return getABIRegister(Integer.parseInt(rd, 2));
    }

    private void disCSR() {
        switch (funct3) {
            case (0b001):
                operation = "csrrw";
                break;
            case (0b010):
                operation = "csrrs";
                break;
            case (0b011):
                operation = "csrrc";
                break;
            case (0b101):
                operation = "csrrwi";
                break;
            case (0b110):
                operation = "csrrsi";
                break;
            case (0b111):
                operation = "csrrci";
                break;
        }
    }

    private void disB() {
        switch (funct3) {
            case (0b000):
                operation = "beq";
                break;
            case (0b001):
                operation = "bne";
                break;
            case (0b100):
                operation = "blt";
                break;
            case (0b101):
                operation = "bge";
                break;
            case (0b110):
                operation = "bltu";
                break;
            case (0b111):
                operation = "bgeu";
                break;
        }
    }

    private void disIarithm(String word) {
        switch (funct3) {
            case (0b000):
                operation = "addi";
                break;
            case (0b010):
                operation = "slti";
                break;
            case (0b011):
                operation = "sltiu";
                break;
            case (0b100):
                operation = "xori";
                break;
            case (0b110):
                operation = "ori";
                break;
            case (0b111):
                operation = "andi";
                break;
            case (0b001):
                operation = "slli";
                break;
            case (0b101):
                if (word.charAt(1) == '0') operation = "srli";
                else operation = "srai";
                break;
        }
    }

    private void disIload() {
        switch (funct3) {
            case (0b000):
                operation = "lb";
                break;
            case (0b001):
                operation = "lh";
                break;
            case (0b010):
                operation = "lw";
                break;
            case (0b100):
                operation = "lbu";
                break;
            case (0b101):
                operation = "lhu";
                break;
        }
    }

    private void disJ(String word) {
        StringBuilder sb  = new StringBuilder();
        sb.append(word.substring(0, 1).repeat(12)).append(word, 12, 20)
                .append(word.charAt(11)).append(word, 1, 11).append("0");
        imm = (int) Long.parseLong(String.valueOf(sb),2);

    }

    private void disS() {
        switch (funct3) {
            case 0b000:
                operation = "sb";
                break;
            case 0b001:
                operation = "sh";
                break;
            case 0b010:
                operation = "sw";
                break;
        }

        imm = rd | ((imm110 >>> 5) << 5);
    }

    private void disR(String word) {
        switch (funct3) {
            case 0b000:
                if (word.charAt(6) == '1') operation = "mul";
                else if (word.charAt(1) == '0') operation = "add";
                else operation = "sub";
                break;
            case 0b001:
                if (word.charAt(6) == '1') operation = "mulh";
                else operation = "sll";
                break;
            case 0b010:
                if (word.charAt(6) == '1') operation = "mulsu";
                else operation = "slt";
                break;
            case 0b011:
                if (word.charAt(6) == '1') operation = "mulu";
                else operation = "sltu";
                break;
            case 0b100:
                if (word.charAt(6) == '1') operation = "div";
                else operation = "xor";
            case 0b101:
                if (word.charAt(6) == '1') operation = "divu";
                else if (word.charAt(1) == '0') operation = "srl";
                else operation = "sra";
                break;
            case 0b110:
                if (word.charAt(6) == '1') operation = "rem";
                else operation = "or";
                break;
            case 0b111:
                if (word.charAt(6) == '1') operation = "remu";
                else operation = "and";
                break;
        }

    }

    private String getRegister(int decimalReg) {
        if (decimalReg == 0) return "zero";
        if (decimalReg == 1) return "ra";
        if (decimalReg == 2) return "sp";
        if (decimalReg == 3) return "gp";
        if (decimalReg == 4) return "tp";
        if (decimalReg >= 5 && decimalReg <= 7) return "t" + (decimalReg - 5);
        if (decimalReg >= 8 && decimalReg <= 9) return "s" + (decimalReg - 8);
        if (decimalReg >= 10 && decimalReg <= 17) return "a" + (decimalReg - 10);
        if (decimalReg >= 18 && decimalReg <= 27) return "s" + (decimalReg - 16);
        if (decimalReg >= 28 && decimalReg <= 31) return "t" + (decimalReg - 25);
        throw new AssertionError("Unknown register: " + decimalReg);
    }

    private String getRegister(String binReg) {
        return getRegister(Integer.parseInt(binReg, 2));
    }



    public void doDisassemble(String input) throws IOException {
        output.println(".text");

        BufferedInputStream stream = new BufferedInputStream(new FileInputStream(input));
        elf = new ELF32File(stream);
        elf.setStreamName(input);
        elf.checkHeader();
        elf.getSections();
        elf.readSectionsNames();
        elf.getStringTableToString();
        elf.getSymTable();
        ELF32File elfText = elf.prepareTextSection();
        prepareMarks(elfText);
        elfText = elf.prepareTextSection();
        int bytesRead = 0;
        addr = elf.addr;
        while (bytesRead < elf.textSize) {
            String next = elf.textSectionNext(elfText);
            if (next.endsWith("11")) {// Это не RVC модификация
                String next2 = elf.textSectionNext(elfText);
                disassemble(next2 + next);
                addr += 4;
                bytesRead += 4;
            } else { // Это RVC модификация
                disassemble(next);
                addr += 2;
                bytesRead += 2;
            }
        }


        output.println();
        output.println(".symtab");
        elf.printSymTab(output);
        output.flush();
        stream.close();

    }

    private void prepareMarks(ELF32File elfText) throws IOException {
        int bytesRead = 0;
        addr = elf.addr;
        while (bytesRead < elf.textSize) {

            String next = elf.textSectionNext(elfText);
            if (next.endsWith("11")) { //не RVC
                String next2 = elf.textSectionNext(elfText);
                String word = next2 + next;
                decimalWord = (int) Long.parseLong(word, 2);
                getUsefulThingsFromWord();
                if (opcode == 0b1101111) { // J-type, jal
                    StringBuilder sb = new StringBuilder();
                    sb.append(word.substring(0, 1).repeat(12)).append(word, 12, 20)
                            .append(word.charAt(11)).append(word, 1, 11).append("0");
                    int imm_j = (int) Long.parseLong(String.valueOf(sb), 2);
                    long jumpTo = addr + imm_j;
                    unknownMarks.add(jumpTo);
                } else if (opcode == 0b1100011) {// B-type
                    StringBuilder sb = new StringBuilder();
                    sb.append(String.valueOf(word.charAt(0)).repeat(20)).append(word.charAt(24))
                            .append(word, 1, 7).append(word, 20, 25).append("0");
                    int imm_b = (int) Long.parseLong(String.valueOf(sb), 2);
                    long jumpTo = addr + imm_b;
                    unknownMarks.add(jumpTo);
                }
                addr += 4;
                bytesRead += 4;
            }
            else { //Это RVC
                opcode = decimalWord & ((1 << 2) - 1);
                funct3 = decimalWord >>> 13;
                short imm;
                int uimm;

                if (opcode == 0b01 && funct3 == 0b001 || opcode == 0b01 && funct3 == 0b101) { //c.jal or c.j
                    imm = getImmForRVCJumps(next);
                    long jumpTo = addr + imm;
                    unknownMarks.add(jumpTo);
                } else if (opcode == 0b01 && funct3 == 110 || opcode == 0b01 && funct3 == 111) { //c.beqz or c.bnez
                    imm = (short) Integer.parseInt(String.valueOf(next.charAt(3)).repeat(7) +
                            next.charAt(3) + next.substring(9, 11) + next.charAt(13) + next.substring(4, 6) +
                            next.substring(11, 13) + "0", 2);
                    long jumpTo = addr + imm;
                    unknownMarks.add(jumpTo);
                }
                addr += 2;
                bytesRead += 2;
            }
        }
    }
}
