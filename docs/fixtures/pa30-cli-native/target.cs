namespace OriginalDeltaFixture {
    public class Beta {
        public static long Combine(long value) { return value ^ 0x200000003L; }
        public static string Echo(string value) { return "target beta:" + value; }
    }
    public class Alpha {
        public static int Mix(int value) {
            int sum = 1;
            for (int i = 0; i < 9; i++) {
                switch ((value + i) % 5) {
                    case 0: sum += 13; break;
                    case 1: sum -= 9; break;
                    case 2: sum ^= value; break;
                    case 3: sum += Add(i); break;
                    default: sum += i * 5; break;
                }
            }
            return sum;
        }
        public static string Label() { return "target alpha"; }
        public static int Add(int value) { return value + 19; }
    }
}
