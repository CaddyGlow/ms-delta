namespace ManagedSignatureFixture {
[System.AttributeUsage(System.AttributeTargets.All)] public class NoteAttribute : System.Attribute { public string Text; public int Number; public System.Type Target { get; set; } public NoteAttribute(string text, int number) { Text = text; Number = number; } }

public delegate int Notify(int value);
public interface IHolder<T> { T Value { get; set; } event Notify Changed; }
public enum Marker : short { First = 1, Second = 2 }
[Note("source holder", 17, Target = typeof(Item))]
 public class Holder<T> : IHolder<T> where T : class, new() {
 public volatile int Counter;
 public T Value { get; set; }
 public event Notify Changed;
 public static U Identity<U>(U value) where U : struct { return value; }
 public static T[] Vector(T value) { return new T[] { value }; }
 public static T[,] Matrix(T value) { T[,] result = new T[2,3]; result[1,2] = value; return result; }
 public static int ByReference(ref int value, out int other) { other = value + 17; value++; return other; }
 public static T Create() { return new T(); }
 public int Fire(int input) { Notify handler = Changed; return handler == null ? -17 : handler(input); }
 public static object Boxed() { return Identity<int>(17); }
 public static string Label() { return "source signature data"; }
}
public class Item { public int Number; public string Text; }
public class Helpers {
 [Note("source method", 17, Target = typeof(Holder<Item>))]
 public static int Increment([Note("source parameter", 17)] int value) { return value + 17; }
 public static Notify MakeDelegate() { return new Notify(Increment); }
 public static System.Collections.Generic.List<Item> List(Item value) { return new System.Collections.Generic.List<Item>(new Item[] { value }); }
 public static int UseGeneric(Item value) { Holder<Item> holder = new Holder<Item>(); holder.Value = value; holder.Changed += MakeDelegate(); int number = holder.Fire(17); holder.Changed -= MakeDelegate(); return number; }
 public static Marker Select(int value) { return value == 17 ? Marker.First : Marker.Second; }
}
}
