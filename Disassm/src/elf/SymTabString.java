package elf;

public class SymTabString {
    int num;
    long value;
    int size;
    String type;
    String bind;
    String vis;
    String index;
    int name;
    String stringName;

    @Override
    public String toString() {
        if (stringName == null) {
            stringName = "";
        }
        return num + " " + value + " " + size + " " + type + " " + bind + " " + vis + " " + index + " " + stringName;
    }
}
