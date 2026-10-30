package du;

import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.array.IntArray;

import java.io.PrintStream;
import java.lang.reflect.*;
import java.util.*;

/** Routes every JNI callback from libdu into one dispatcher: custom fakes first, then real JDK reflection, else MISS. */
public class Bridge implements InvocationHandler {
    public interface Handler { Object handle(DvmObject<?> self, Object[] args) throws Exception; }

    final BaseVM vm;
    final PrintStream trace;
    final Map<String, Handler> handlers = new HashMap<>();
    final Map<String, Object> staticFields = new HashMap<>();
    final Set<String> misses = new LinkedHashSet<>();
    final Map<DvmObject<?>, Map<String, Object>> instFields = new IdentityHashMap<>();

    Bridge(BaseVM vm, PrintStream trace) { this.vm = vm; this.trace = trace; }

    public Jni asJni() {
        return (Jni) Proxy.newProxyInstance(Jni.class.getClassLoader(), new Class[]{Jni.class}, this);
    }

    @Override
    public Object invoke(Object proxy, Method m, Object[] a) {
        String name = m.getName();
        switch (name) {
            case "acceptMethod": case "acceptField": return true;
            case "hashCode": return System.identityHashCode(this);
            case "equals": return proxy == a[0];
            case "toString": return "Bridge";
        }
        boolean isStatic = name.contains("Static") || name.startsWith("newObject") || name.equals("allocObject") || name.equals("toReflectedMethod");
        DvmClass cls = a[1] instanceof DvmClass ? (DvmClass) a[1] : ((DvmObject<?>) a[1]).getObjectType();
        DvmObject<?> self = isStatic ? null : (DvmObject<?>) a[1];
        String sig;
        if (a[2] instanceof DvmMethod dm) sig = dm.getDvmClass().getClassName() + "->" + dm.getMethodName() + dm.getArgs();
        else if (a[2] instanceof DvmField df) sig = df.getDvmClass().getClassName() + "->" + df.getFieldName() + ":" + df.getFieldType();
        else sig = (String) a[2];
        Class<?> ret = m.getReturnType();
        if (name.equals("allocObject")) return cls.newObject(null);
        if (name.equals("toReflectedMethod")) return null;
        boolean isField = name.endsWith("Field");
        if (isField) sig = normalizeFieldSig(sig);
        if (isField && name.startsWith("set")) {
            Object v = a[3];
            if (self == null) staticFields.put(sig, v); else fieldStore(self).put(sig, v);
            trace.println("SET " + sig + (self == null ? "" : " on " + show(self)) + " = " + show(v));
            return null;
        }
        if (isField) {
            Object v = getField(self, sig);
            trace.println("GET " + sig + (self == null ? "" : " on " + show(self)) + " => " + show(v));
            return coerce(v, ret);
        }
        VarArg va = (VarArg) a[3];
        String desc = sig.substring(sig.indexOf('('));
        List<String> ptypes = paramTypes(desc);
        Object[] args = new Object[ptypes.size()];
        for (int i = 0; i < args.length; i++) args[i] = readArg(va, i, ptypes.get(i));
        Object r;
        try {
            r = dispatch(sig, self, args, desc, name.startsWith("newObject"));
        } catch (Throwable t) {
            Throwable c = t instanceof InvocationTargetException ite ? ite.getCause() : t;
            trace.println("THROW " + sig + " " + c);
            r = null;
        }
        trace.println("CALL " + sig + (self == null ? "" : " on " + show(self)) + " args=" + show(args) + " => " + show(r));
        return coerce(r, ret);
    }

    /** unidbg passes field sigs as "cls->nameType" for the String overloads; make them "cls->name:Type". */
    static String normalizeFieldSig(String sig) {
        if (sig.contains(":")) return sig;
        int arrow = sig.indexOf("->") + 2;
        String rest = sig.substring(arrow);
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            boolean prim = "IJZBSCFD".indexOf(c) >= 0 && i == rest.length() - 1;
            if (c == 'L' && rest.endsWith(";") && rest.indexOf('/', i) > 0 || c == '[' || prim)
                if (i > 0) return sig.substring(0, arrow) + rest.substring(0, i) + ":" + rest.substring(i);
        }
        return sig;
    }

    Map<String, Object> fieldStore(DvmObject<?> o) { return instFields.computeIfAbsent(o, k -> new HashMap<>()); }

    Object getField(DvmObject<?> self, String sig) {
        Map<String, Object> store = self == null ? staticFields : fieldStore(self);
        if (store.containsKey(sig)) return store.get(sig);
        Handler h = handlers.get("FIELD " + sig);
        if (h == null && self != null) h = handlers.get("FIELD *" + sig.substring(sig.indexOf("->")));
        try {
            if (h != null) return h.handle(self, new Object[0]);
            String owner = sig.substring(0, sig.indexOf("->")), fname = sig.substring(sig.indexOf("->") + 2, sig.indexOf(':'));
            Object target = self == null ? null : self.getValue();
            Class<?> c = forName(owner);
            if (c != null && reflectable(c.getName()) && (self == null || c.isInstance(target))) return wrap(c.getField(fname).get(target));
        } catch (Throwable t) {
            trace.println("THROW FIELD " + sig + " " + t);
        }
        misses.add("FIELD " + sig);
        return null;
    }

    Handler findHandler(String sig) {
        Handler h = handlers.get(sig);
        if (h != null) return h;
        String owner = sig.substring(0, sig.indexOf("->"));
        String tail = sig.substring(sig.indexOf("->"));
        for (DvmClass c = vm.resolveClass(owner).getSuperclass(); c != null; c = c.getSuperclass())
            if ((h = handlers.get(c.getClassName() + tail)) != null) return h;
        return handlers.get("*" + tail);
    }

    Object dispatch(String sig, DvmObject<?> self, Object[] args, String desc, boolean ctor) throws Throwable {
        Handler h = findHandler(sig);
        if (h != null) return h.handle(self, args);
        String owner = sig.substring(0, sig.indexOf("->"));
        String mname = sig.substring(sig.indexOf("->") + 2, sig.indexOf('('));
        Object target = self == null ? null : self.getValue();
        Class<?> declared = forName(owner);
        // only run real JDK code when the receiver really is an instance of the JNI-declared JDK class
        Class<?> c = declared == null || !reflectable(declared.getName()) ? null
                : ctor || self == null ? declared : declared.isInstance(target) ? target.getClass() : null;
        if (c != null) {
            Class<?>[] pts = paramClasses(desc);
            Object[] jargs = new Object[args.length];
            for (int i = 0; i < args.length; i++) jargs[i] = unwrapArg(args[i], pts[i]);
            if (ctor) return wrap(c.getConstructor(pts).newInstance(jargs));
            Method jm = findMethod(c, mname, pts);
            return wrap(jm.invoke(Modifier.isStatic(jm.getModifiers()) ? null : target, jargs));
        }
        misses.add(sig);
        if (ctor) return vm.resolveClass(owner).newObject(null);
        return placeholder(desc.substring(desc.indexOf(')') + 1), sig);
    }

    /** Unknown object-returning call: real devices almost never return null there, and libdu crashes on null receivers. */
    DvmObject<?> placeholder(String rt, String sig) {
        if (rt.equals("Ljava/lang/String;") || rt.equals("Ljava/lang/Object;") || rt.equals("Ljava/lang/CharSequence;")) return null;
        if (rt.startsWith("[B")) return new ByteArray(vm, new byte[0]);
        if (rt.startsWith("[I")) return new IntArray(vm, new int[0]);
        if (rt.startsWith("[")) return new ArrayObject();
        if (rt.startsWith("L")) return vm.resolveClass(rt.substring(1, rt.length() - 1)).newObject("fake:" + sig);
        return null;
    }

    static Method findMethod(Class<?> c, String n, Class<?>[] pts) throws NoSuchMethodException {
        for (Class<?> k = c; k != null; k = k.getSuperclass()) {
            if (Modifier.isPublic(k.getModifiers())) try { return k.getMethod(n, pts); } catch (NoSuchMethodException ignored) { }
            for (Class<?> i : k.getInterfaces()) try { return i.getMethod(n, pts); } catch (NoSuchMethodException ignored) { }
        }
        return c.getMethod(n, pts);
    }

    /** Only pure-compute JDK classes may run for real; anything touching host network, files, processes is faked. */
    static boolean reflectable(String cn) {
        if (cn.startsWith("java.net.") || cn.startsWith("javax.net.") || cn.startsWith("java.io.File") || cn.startsWith("java.nio.file")
                || cn.equals("java.lang.Runtime") || cn.equals("java.lang.ProcessBuilder") || cn.equals("java.lang.System")
                || cn.startsWith("java.lang.reflect.") || cn.equals("java.lang.Class") || cn.equals("java.lang.ClassLoader")
                || cn.equals("java.lang.Thread") || cn.startsWith("java.security.KeyStore")) return false;
        return cn.startsWith("java.") || cn.startsWith("javax.crypto.") || cn.startsWith("org.json.");
    }

    static Class<?> forName(String internal) {
        try { return Class.forName(internal.replace('/', '.')); } catch (Throwable t) { return null; }
    }

    static Object unwrapArg(Object a, Class<?> pt) {
        if (a instanceof ArrayObject ao) {
            DvmObject<?>[] els = ao.getValue();
            Object arr = java.lang.reflect.Array.newInstance(pt.isArray() ? pt.getComponentType() : Object.class, els.length);
            for (int i = 0; i < els.length; i++) java.lang.reflect.Array.set(arr, i, els[i] == null ? null : els[i].getValue());
            return arr;
        }
        if (a instanceof DvmObject<?> d) return d.getValue();
        return a;
    }

    public DvmObject<?> wrap(Object v) {
        if (v == null || v instanceof Number || v instanceof Boolean || v instanceof Character) return null;
        if (v instanceof DvmObject<?> d) return d;
        if (v instanceof String s) return new StringObject(vm, s);
        if (v instanceof byte[] b) return new ByteArray(vm, b);
        if (v instanceof int[] ia) return new IntArray(vm, ia);
        if (v instanceof Object[] arr) {
            DvmObject<?>[] out = new DvmObject[arr.length];
            for (int i = 0; i < arr.length; i++) out[i] = wrap(arr[i]);
            return new ArrayObject(out);
        }
        return vm.resolveClass(v.getClass().getName().replace('.', '/')).newObject(v);
    }

    /** Primitive results pass through as boxed values; objects get wrapped. */
    Object coerce(Object r, Class<?> ret) {
        if (ret == void.class) return null;
        if (ret == boolean.class) return r instanceof Boolean b ? b : r instanceof Number n && n.intValue() != 0;
        if (ret == int.class) return r instanceof Number n ? n.intValue() : r instanceof Boolean b ? (b ? 1 : 0) : r instanceof Character ch ? (int) ch : 0;
        if (ret == long.class) return r instanceof Number n ? n.longValue() : 0L;
        if (ret == float.class) return r instanceof Number n ? n.floatValue() : 0f;
        if (ret == double.class) return r instanceof Number n ? n.doubleValue() : 0d;
        if (ret == byte.class) return r instanceof Number n ? n.byteValue() : (byte) 0;
        if (ret == short.class) return r instanceof Number n ? n.shortValue() : (short) 0;
        if (ret == char.class) return r instanceof Character ch ? ch : (char) 0;
        if (r == null || r instanceof DvmObject) return r;
        return wrap(r);
    }

    static Object readArg(VarArg va, int i, String t) {
        switch (t.charAt(0)) {
            case 'Z': return va.getIntArg(i) != 0;
            case 'B': return (byte) va.getIntArg(i);
            case 'S': return (short) va.getIntArg(i);
            case 'C': return (char) va.getIntArg(i);
            case 'I': return va.getIntArg(i);
            case 'J': return va.getLongArg(i);
            case 'F': return va.getFloatArg(i);
            case 'D': return va.getDoubleArg(i);
            default: return va.getObjectArg(i);
        }
    }

    static List<String> paramTypes(String desc) {
        List<String> out = new ArrayList<>();
        int i = 1;
        while (desc.charAt(i) != ')') {
            int s = i;
            while (desc.charAt(i) == '[') i++;
            if (desc.charAt(i) == 'L') i = desc.indexOf(';', i);
            i++;
            out.add(desc.substring(s, i));
        }
        return out;
    }

    static Class<?>[] paramClasses(String desc) throws ClassNotFoundException {
        List<String> ts = paramTypes(desc);
        Class<?>[] out = new Class[ts.size()];
        for (int i = 0; i < out.length; i++) out[i] = typeClass(ts.get(i));
        return out;
    }

    static Class<?> typeClass(String t) throws ClassNotFoundException {
        switch (t) {
            case "Z": return boolean.class; case "B": return byte.class; case "S": return short.class; case "C": return char.class;
            case "I": return int.class; case "J": return long.class; case "F": return float.class; case "D": return double.class;
        }
        if (t.startsWith("[")) {
            try { return Class.forName(t.replace('/', '.')); } catch (ClassNotFoundException e) { return Object[].class; }
        }
        try { return Class.forName(t.substring(1, t.length() - 1).replace('/', '.')); } catch (ClassNotFoundException e) { return Object.class; }
    }

    public static String show(Object o) {
        if (o == null) return "null";
        if (o instanceof Object[] arr) { StringBuilder sb = new StringBuilder("["); for (Object x : arr) sb.append(show(x)).append(", "); return sb.append("]").toString(); }
        if (o instanceof ByteArray ba) return "bytes[" + ba.getValue().length + "]:" + hex(ba.getValue(), 512) + " |" + printable(ba.getValue(), 1024) + "|";
        if (o instanceof StringObject so) return "\"" + trunc(so.getValue(), 20000) + "\"";
        if (o instanceof IntArray ia) return Arrays.toString(ia.getValue());
        if (o instanceof ArrayObject ao) return show((Object[]) ao.getValue());
        if (o instanceof DvmObject<?> d) return d.getObjectType().getClassName() + "{" + trunc(String.valueOf(d.getValue()), 300) + "}";
        return String.valueOf(o);
    }
    static String trunc(String s, int n) { return s == null ? "null" : s.length() > n ? s.substring(0, n) + "...(" + s.length() + ")" : s; }
    public static String hex(byte[] b, int n) { StringBuilder sb = new StringBuilder(); for (int i = 0; i < Math.min(n, b.length); i++) sb.append(String.format("%02x", b[i])); return sb.toString(); }
    static String printable(byte[] b, int n) { StringBuilder sb = new StringBuilder(); for (int i = 0; i < Math.min(n, b.length); i++) sb.append(b[i] >= 32 && b[i] < 127 ? (char) b[i] : '.'); return sb.toString(); }
}
