import java.io.*;
import java.util.InputMismatchException;

public class MainDisassembler {
    public static void main(String[] args) { //args[0] - input, args[1] - output
        String input;
        if (args.length >= 1) {
            input = args[0];
        } else {
            System.err.println("Can't find input file name");
            return;
        }

        try {
            OutputStreamWriter output =
                    new OutputStreamWriter(args.length > 1 ? new FileOutputStream(args[1]) : System.out);
            try {

                RISCVDisassembler dis = new RISCVDisassembler(new PrintWriter(output));
                dis.doDisassemble(input);
            } finally {
                output.close();
            }
        } catch (FileNotFoundException e){
            System.err.println("File not found");
        } catch (IOException e) {
            System.err.println("Something went wrong");
        } catch (InputMismatchException e) {
            System.err.println("Somethind went wrong: " + e);
        }

    }
}
