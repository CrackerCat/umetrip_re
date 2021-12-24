package com.umetrip.android.msky.app;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.SystemPropertyHook;
import com.github.unidbg.linux.android.SystemPropertyProvider;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;

import org.apache.commons.codec.binary.Base64;

import java.awt.geom.RectangularShape;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import king.trace.GlobalData;
import king.trace.KingTrace;

public class umetrip extends AbstractJni{
    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;

    umetrip() {
        emulator = AndroidEmulatorBuilder.for32Bit().setProcessName("com.umetrip.android.msky.app").build(); // 创建模拟器实例，要模拟32位或者64位，在这里区分
        final Memory memory = emulator.getMemory(); // 模拟器的内存操作接口
        memory.setLibraryResolver(new AndroidResolver(23)); // 设置系统类库解析
        vm = emulator.createDalvikVM(new File("E:\\unidbg-0.9.5\\unidbg-android\\src\\test\\resources\\example_binaries\\umetrip\\hlzh_7.1.6.apk"));
        vm.setVerbose(true);

        DalvikModule dm = vm.loadLibrary(new File("E:\\unidbg-0.9.5\\unidbg-android\\src\\test\\resources\\example_binaries\\umetrip\\libumejni.so"), true);

        vm.setJni(this);
        module = dm.getModule();
//        emulator.traceCode(module.base, module.base + module.size);

        System.out.println("call JNIOnLoad");
        dm.callJNI_OnLoad(emulator);
    }
    public void callSub_0515() {
        List<Object> list = new ArrayList<>(10);
        String data = "{\"lastReqTime\":\"8151\",\"lastTransactionID\":\"1267d11000331602210574619\",\"latitude\":\"23.083936\",\"longitude\":\"113.231597\",\"netType\":\"1\",\"pageId\":\"110300\"," +
                "\"rchannel\":\"10000025\",\"rcuuid\":\"1267df7f194d74c5f922c5295499b92ee\"," +
                "\"rcver\":\"AND_a01_06.51.0914\",\"rkey\":\"2020-10-09 10:30:46 8000\"," +
                "\"rparams\":{\"mobile\":\"13188886666\",\"passWord\":\"123456789abcdef\",\"rttimestamp\":0,\"validateCode\":\"\"}," +
                "\"rpid\":\"1100033\",\"rpver\":\"3.0\",\"rsid\":\"\",\"transactionID\":\"1267d11000331602210646184\"}";
        DvmObject context = vm.resolveClass("android/content/Context").newObject(null);
        list.add(vm.getJNIEnv()); // 第一个参数是env
        list.add(0); // 第二个参数，实例方法是jobject，静态方法是jclazz，直接填0，一般用不到。
        list.add(vm.addLocalObject(context));
        list.add(vm.addLocalObject(new StringObject(vm, data)));
        //trace code
//        GlobalData.ignoreModuleList.add("libc.so");
//        GlobalData.ignoreModuleList.add("libhookzz.so");
//        GlobalData.watch_address.put(0x4001259b,"");
//        GlobalData.is_dump_ldr=true;
//        GlobalData.is_dump_str=true;
//        KingTrace trace=new KingTrace(emulator);
//        trace.initialize(1,0,null);
//        emulator.getBackend().hook_add_new(trace,1,0,emulator);
        emulator.attach().addBreakPoint(module.base + 0x000139E0);
        module.callFunction(emulator, 0x0000B805, list.toArray());

    }

    public static void main(String[] args) {
        umetrip test = new umetrip();
        test.callSub_0515();
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, DvmMethod dvmMethod, VarArg varArg) {
        switch (dvmMethod.getSignature()) {
            case "com/ume/android/lib/common/storage/PreferenceData->getPFlag()Z":
                return true;
        }
        return super.callStaticBooleanMethod(vm, dvmClass, dvmMethod, varArg);

    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "com/umetrip/android/msky/app/BuildConfig->uWyMrFzw:Ljava/lang/String;":
                return new StringObject(vm, "L_2QCh>");

        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }
}
