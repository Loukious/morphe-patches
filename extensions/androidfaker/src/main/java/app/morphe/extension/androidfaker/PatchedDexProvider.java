package app.morphe.extension.androidfaker;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Runtime DEX extractor used by patched Native.getDex().
 *
 * The patched APK bypasses System.loadLibrary("af_native") to avoid native anti-tamper,
 * so JNI getDex() is unavailable. This helper recovers the encrypted DEX payload from
 * libaf_native.so and decrypts it using the same XOR key the native code expects.
 */
public final class PatchedDexProvider {
    private static final String FAKER_PACKAGE = "com.android1500.androidfaker";
    private static final String SO_NAME = "libaf_native.so";
    private static final byte XOR_KEY = 0x32;
    private static final int DEX_FILE_SIZE_OFFSET = 32;
    private static final byte[] EMPTY = new byte[0];

    private PatchedDexProvider() {}

    public static byte[] get() {
        try {
            ApplicationInfo appInfo = getFakerAppInfo();
            if (appInfo == null) {
                return EMPTY;
            }

            if (appInfo.nativeLibraryDir != null) {
                byte[] dex = fromNativeLibraryDir(appInfo.nativeLibraryDir);
                if (dex.length != 0) {
                    return dex;
                }
            }

            if (appInfo.sourceDir != null) {
                byte[] dex = fromApk(appInfo.sourceDir);
                if (dex.length != 0) {
                    return dex;
                }
            }
        } catch (Throwable ignored) {
            // Intentionally swallow all failures and let caller handle empty payload.
        }
        return EMPTY;
    }

    private static ApplicationInfo getFakerAppInfo() {
        Context context = resolveContext();
        if (context == null) {
            return null;
        }

        try {
            return context.getPackageManager().getApplicationInfo(FAKER_PACKAGE, 0);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Context resolveContext() {
        try {
            Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
            Method currentApplication = activityThreadClass.getMethod("currentApplication");
            Object app = currentApplication.invoke(null);
            if (app instanceof Application) {
                return (Context) app;
            }

            Method currentActivityThread = activityThreadClass.getMethod("currentActivityThread");
            Object thread = currentActivityThread.invoke(null);
            if (thread != null) {
                Method getSystemContext = thread.getClass().getMethod("getSystemContext");
                Object systemContext = getSystemContext.invoke(thread);
                if (systemContext instanceof Context) {
                    return (Context) systemContext;
                }
            }
        } catch (Throwable ignored) {
            // fall through
        }
        return null;
    }

    private static byte[] fromNativeLibraryDir(String nativeLibraryDir) {
        try {
            File soFile = new File(nativeLibraryDir, SO_NAME);
            if (!soFile.exists() || !soFile.isFile()) {
                return EMPTY;
            }
            return decrypt(readFully(soFile));
        } catch (Throwable ignored) {
            return EMPTY;
        }
    }

    private static byte[] fromApk(String sourceApkPath) {
        try (ZipFile zipFile = new ZipFile(sourceApkPath)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith("/" + SO_NAME)) {
                    continue;
                }

                try (InputStream inputStream = zipFile.getInputStream(entry);
                     ByteArrayOutputStream output = new ByteArrayOutputStream()) {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = inputStream.read(buffer)) != -1) {
                        output.write(buffer, 0, read);
                    }
                    byte[] dex = decrypt(output.toByteArray());
                    if (dex.length != 0) {
                        return dex;
                    }
                }
            }
        } catch (Throwable ignored) {
            // ignore
        }

        return EMPTY;
    }

    private static byte[] decrypt(byte[] soBytes) {
        if (soBytes == null || soBytes.length < 64) {
            return EMPTY;
        }

        final byte encMagic0 = 0x56;
        final byte encMagic1 = 0x57;
        final byte encMagic2 = 0x4A;

        for (int i = 0, limit = soBytes.length - 64; i <= limit; i++) {
            if (soBytes[i] != encMagic0 || soBytes[i + 1] != encMagic1 || soBytes[i + 2] != encMagic2) {
                continue;
            }
            if ((soBytes[i + 3] ^ XOR_KEY) != '\n') {
                continue;
            }

            int fileSizeOffset = i + DEX_FILE_SIZE_OFFSET;
            if (fileSizeOffset + 4 > soBytes.length) {
                continue;
            }

            int dexSize = littleEndianXorInt(soBytes, fileSizeOffset);
            if (dexSize <= 0 || i + dexSize > soBytes.length) {
                continue;
            }

            byte[] dexBytes = new byte[dexSize];
            for (int k = 0; k < dexSize; k++) {
                dexBytes[k] = (byte) (soBytes[i + k] ^ XOR_KEY);
            }

            if (dexBytes.length >= 3 && dexBytes[0] == 'd' && dexBytes[1] == 'e' && dexBytes[2] == 'x') {
                return dexBytes;
            }
        }

        return EMPTY;
    }

    private static int littleEndianXorInt(byte[] data, int offset) {
        return ((data[offset] ^ XOR_KEY) & 0xFF)
                | (((data[offset + 1] ^ XOR_KEY) & 0xFF) << 8)
                | (((data[offset + 2] ^ XOR_KEY) & 0xFF) << 16)
                | (((data[offset + 3] ^ XOR_KEY) & 0xFF) << 24);
    }

    private static byte[] readFully(File file) throws IOException {
        long fileLength = file.length();
        if (fileLength <= 0 || fileLength > 64L * 1024L * 1024L) {
            return EMPTY;
        }

        byte[] data = new byte[(int) fileLength];
        try (FileInputStream input = new FileInputStream(file)) {
            int read = 0;
            while (read < data.length) {
                int n = input.read(data, read, data.length - read);
                if (n < 0) {
                    break;
                }
                read += n;
            }
            if (read != data.length) {
                return EMPTY;
            }
        }
        return data;
    }
}
