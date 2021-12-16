package elf;

public class Section {
    public int name; //Смещение относительно начала таблицы названий
    public SH_TYPE type;
    public int offset;
    public int size;
    public String link;
    public String entsize;
    public String stringName;
    public String addr = "0";

    @Override
    public String toString() {
        return addr + " " + type + " " +  offset + " " + size + " " + link + " " + entsize
                + " " + stringName;
    }
}
