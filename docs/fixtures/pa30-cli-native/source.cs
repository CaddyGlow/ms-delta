namespace OriginalDeltaFixture {
    public class Alpha {
        public static int Add(int value) { return value + 17; }
        public static string Label() { return "source alpha"; }
        public static int Mix(int value) {
            int sum = 0;
            for (int i = 0; i < 7; i++) {
                switch ((value + i) % 5) {
                    case 0: sum += 11; break;
                    case 1: sum -= 7; break;
                    case 2: sum ^= value; break;
                    case 3: sum += Add(i); break;
                    default: sum += i * 3; break;
                }
            }
            return sum;
        }
    }
    public class Beta {
        public static string Echo(string value) { return "source beta:" + value; }
        public static long Combine(long value) { return value ^ 0x100000001L; }
    }
}
