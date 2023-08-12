package solver;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.VarHandle;

final class SHA2WithIntrinsics extends SHA2 {

    private static final MethodHandle MH_COMPRESS;
    private static final VarHandle MH_SET_STATE;
    private static final VarHandle MH_SET_W;
    private static final MethodHandle MH_CONSTRUCT;

    static {
        try {
            Class<?> sha2 = Class.forName("sun.security.provider.SHA2");
            MethodHandles.Lookup caller = MethodHandles.lookup();
            MethodHandles.Lookup sha2Lookup = MethodHandles.privateLookupIn(
                    sha2,
                    caller
            );
            MH_COMPRESS = sha2Lookup.findVirtual(sha2, "implCompress0", MethodType.methodType(void.class, byte[].class, int.class))
                    .asType(MethodType.methodType(void.class, Object.class, byte[].class, int.class));
            MH_SET_STATE = sha2Lookup.findVarHandle(sha2, "state", int[].class).withInvokeBehavior();
            MH_SET_W = sha2Lookup.findVarHandle(sha2, "W", int[].class).withInvokeBehavior();
            sha2 = Class.forName("sun.security.provider.SHA2$SHA256");
            MH_CONSTRUCT = MethodHandles.privateLookupIn(
                            sha2,
                            caller
                    ).findConstructor(sha2, MethodType.methodType(void.class))
                    .asType(MethodType.genericMethodType(0));
        } catch (ReflectiveOperationException ex) {
            throw new ExceptionInInitializerError(ex);
        }
    }

    final Object impl;

    SHA2WithIntrinsics() {
        try {
            Object impl = MH_CONSTRUCT.invokeExact();
            MH_SET_STATE.set(impl, state);
            MH_SET_W.set(impl, W);
            this.impl = impl;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    @Override
    void implCompress0(int[] W, int[] state, byte[] buf) {
        try {
            MH_COMPRESS.invokeExact(impl, buf, 0);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }
}
