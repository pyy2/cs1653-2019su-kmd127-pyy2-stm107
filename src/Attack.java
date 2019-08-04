import java.lang.String;
import java.util.concurrent.TimeUnit;

public class Attack {

    public static void main(String[] args) throws InterruptedException {

        String password = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        String[] attempt = new String[3];
        attempt[0] = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        attempt[1] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaazzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        attempt[2] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        long[] total = new long[3];
        for (int i = 0; i < total.length; i++) {
            total[i] = 0;
        }

        long nano_startTime = 12345678910L;
        long nano_endTime = 12345678910L;

        for (int i = 0; i < 100000; i++) {
            for (int j = 0; j < attempt.length; j++) {
                nano_startTime = System.nanoTime();
                password.compareTo(attempt[j]);
                nano_endTime = System.nanoTime();
                total[j] += nano_endTime - nano_startTime;
            }
        }

        System.out.println("equals");

        for (int i = 0; i < total.length; i++) {
            System.out.println(Long.toString(total[i] / 100000));
        }

        // for (int i = 0; i < 10000; i++) {
        // for (int j = 0; j < attempt.length; j++) {
        // TimeUnit.MILLISECONDS.wait(1);

        // nano_startTime = System.nanoTime();
        // password.compareTo(attempt[j]);
        // nano_endTime = System.nanoTime();
        // total[j] += nano_endTime - nano_startTime;
        // }
        // }

        // System.out.println("compareto");

        // for (int i = 0; i < total.length; i++) {
        // System.out.println(Long.toString(total[i] / 100000));
        // }

        for (int i = 0; i < 100000; i++) {
            for (int j = 0; j < attempt.length; j++) {
                byte[] a = password.getBytes();
                byte[] b = attempt[j].getBytes();
                nano_startTime = System.nanoTime();
                isEqual(b, a);
                nano_endTime = System.nanoTime();
                total[j] += nano_endTime - nano_startTime;
            }
        }

        System.out.println("constant");

        for (int i = 0; i < total.length; i++) {
            System.out.println(Long.toString(total[i] / 100000));
        }
    }

    public static boolean isEqual(byte[] a, byte[] b) {
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
