/*
 * Copyright (C) 2025 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#define LOG_TAG "OplusFodShim"

#include <log/log.h>
#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISession.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <android-base/properties.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>

using aidl::android::hardware::biometrics::fingerprint::ISession;
using aidl::android::hardware::biometrics::fingerprint::ISessionCallback;
using android::base::GetProperty;

namespace {

static const char* kFodNode = "/sys/kernel/oplus_display/notify_fppress";
static const char kSessionDesc[] = "android.hardware.biometrics.fingerprint.ISession";

/*
 * OPlus fingerprint HAL vendor-specific onAcquired codes.
 * The HAL sends these via ISessionCallback::onAcquired to signal finger
 * down/up, even under AOD where the framework's onPointerDown doesn't fire.
 */
static constexpr int32_t kVendorFingerDown = 22;
static constexpr int32_t kVendorFingerUp = 23;

static bool gPressed = false;
static int gFodFd = -1;
static pthread_mutex_t gMutex = PTHREAD_MUTEX_INITIALIZER;

static AIBinder_Class_onTransact gOrigSessionOnTransact = nullptr;

/*
 * Thread-local capture of int32 values written to the current outgoing
 * binder parcel.  We hook AIBinder_prepareTransaction (start) and
 * AParcel_writeInt32 (capture) so that by the time AIBinder_transact fires,
 * we can inspect the payload — specifically the vendor code inside onAcquired.
 */
struct ParcelCapture {
    AParcel* parcel;
    int32_t vals[16];
    int count;
};
static thread_local ParcelCapture gCapture = {nullptr, {0}, 0};

static void writeFodNode(const char* val) {
    if (gFodFd < 0) {
        ALOGE("notify_fppress fd not open");
        return;
    }
    ssize_t ret = pwrite(gFodFd, val, strlen(val), 0);
    ALOGI("notify_fppress <= %s (ret=%zd)", val, ret);
}

static void setPressed(bool pressed) {
    pthread_mutex_lock(&gMutex);
    bool changed = (gPressed != pressed);
    gPressed = pressed;
    pthread_mutex_unlock(&gMutex);

    if (changed) {
        writeFodNode(pressed ? "1" : "0");
    }
}

/* ISession incoming-call wrapper — catches framework onPointerDown/Up */
static binder_status_t sessionOnTransactWrapper(AIBinder* binder, transaction_code_t code,
                                                const AParcel* in, AParcel* out) {
    if (code == ISession::TRANSACTION_onPointerDownWithContext) {
        ALOGI("ISession::onPointerDownWithContext -> HBM on");
        setPressed(true);
    } else if (code == ISession::TRANSACTION_onPointerUpWithContext) {
        ALOGI("ISession::onPointerUpWithContext -> HBM off");
        setPressed(false);
    }
    return gOrigSessionOnTransact(binder, code, in, out);
}

} // namespace

/*
 * Hook: capture the parcel pointer at transaction start.
 */
extern "C"
binder_status_t AIBinder_prepareTransaction(AIBinder* binder, AParcel** in) {
    using Fn = binder_status_t (*)(AIBinder*, AParcel**);
    static auto orig = (Fn)dlsym(RTLD_NEXT, "AIBinder_prepareTransaction");
    if (!orig) return STATUS_UNKNOWN_ERROR;

    binder_status_t st = orig(binder, in);
    gCapture.parcel = (in ? *in : nullptr);
    gCapture.count = 0;
    return st;
}

/*
 * Hook: record every int32 written to the current outgoing parcel.
 */
extern "C"
binder_status_t AParcel_writeInt32(AParcel* parcel, int32_t value) {
    using Fn = binder_status_t (*)(AParcel*, int32_t);
    static auto orig = (Fn)dlsym(RTLD_NEXT, "AParcel_writeInt32");
    if (!orig) return STATUS_UNKNOWN_ERROR;

    if (parcel && parcel == gCapture.parcel &&
        gCapture.count < (int)(sizeof(gCapture.vals) / sizeof(gCapture.vals[0]))) {
        gCapture.vals[gCapture.count++] = value;
    }
    return orig(parcel, value);
}

/*
 * Hook: outgoing binder calls (HAL -> framework callbacks).
 *
 * Catches vendor-specific onAcquired codes 22 (finger down) and 23 (finger up)
 * for deep AOD where the framework's onPointerDown doesn't fire.
 * Also catches session-end events to ensure HBM is always turned off.
 */
extern "C"
binder_status_t AIBinder_transact(AIBinder* binder, transaction_code_t code,
                                  AParcel** in, AParcel** out, binder_flags_t flags) {
    using Fn = binder_status_t (*)(AIBinder*, transaction_code_t, AParcel**, AParcel**, binder_flags_t);
    static auto orig = (Fn)dlsym(RTLD_NEXT, "AIBinder_transact");
    if (!orig) return STATUS_UNKNOWN_ERROR;

    /* onAcquired: inspect parcel for vendor finger down/up codes */
    if (code == ISessionCallback::TRANSACTION_onAcquired &&
        gCapture.parcel && in && *in == gCapture.parcel && gCapture.count > 0) {
        for (int i = 0; i < gCapture.count; ++i) {
            if (gCapture.vals[i] == kVendorFingerDown) {
                ALOGI("onAcquired: vendor finger-down (%d) -> HBM on", kVendorFingerDown);
                setPressed(true);
                break;
            }
            if (gCapture.vals[i] == kVendorFingerUp) {
                ALOGI("onAcquired: vendor finger-up (%d) -> HBM off", kVendorFingerUp);
                setPressed(false);
                break;
            }
        }
    }

    /* Session-end events: ensure HBM is off */
    if (code == ISessionCallback::TRANSACTION_onAuthenticationSucceeded ||
        code == ISessionCallback::TRANSACTION_onError ||
        code == ISessionCallback::TRANSACTION_onSessionClosed) {
        ALOGI("session end (code=%d) -> HBM off", code);
        setPressed(false);
    }

    binder_status_t ret = orig(binder, code, in, out, flags);

    gCapture.parcel = nullptr;
    gCapture.count = 0;
    return ret;
}

/*
 * Hook: binder class registration — wrap ISession to see incoming
 * onPointerDown/onPointerUp calls from the framework.
 */
extern "C"
AIBinder_Class* AIBinder_Class_define(const char* interfaceDescriptor,
                                      AIBinder_Class_onCreate onCreate,
                                      AIBinder_Class_onDestroy onDestroy,
                                      AIBinder_Class_onTransact onTransact) {
    using Fn = AIBinder_Class* (*)(const char*, AIBinder_Class_onCreate,
                                   AIBinder_Class_onDestroy, AIBinder_Class_onTransact);
    static auto orig = (Fn)dlsym(RTLD_NEXT, "AIBinder_Class_define");
    if (!orig) return nullptr;

    if (interfaceDescriptor &&
        strncmp(interfaceDescriptor, kSessionDesc, sizeof(kSessionDesc) - 1) == 0 &&
        (interfaceDescriptor[sizeof(kSessionDesc) - 1] == '\0' ||
         interfaceDescriptor[sizeof(kSessionDesc) - 1] == '/')) {
        ALOGI("Wrapping ISession onTransact (descriptor: %s)", interfaceDescriptor);
        gOrigSessionOnTransact = onTransact;
        return orig(interfaceDescriptor, onCreate, onDestroy, sessionOnTransactWrapper);
    }

    return orig(interfaceDescriptor, onCreate, onDestroy, onTransact);
}

__attribute__((constructor))
static void init() {
    /* Temporarily disabled: testing DRM connector property path for LHBM */
    ALOGI("init: OplusFodShim disabled for DRM property path testing");
    return;

    std::string sensorType = GetProperty("persist.vendor.fingerprint.sensor_type", "");
    if (sensorType != "optical") {
        ALOGI("init: not optical sensor (%s), disabled", sensorType.c_str());
        return;
    }

    gFodFd = open(kFodNode, O_WRONLY | O_CLOEXEC);
    ALOGI("init: notify_fppress fd=%d", gFodFd);
}

__attribute__((destructor))
static void cleanup() {
    setPressed(false);
    if (gFodFd >= 0) {
        close(gFodFd);
        gFodFd = -1;
    }
}
