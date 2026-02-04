/*
 * Copyright (C) 2025 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#define LOG_TAG "OplusFodShim"

#include <android/binder_ibinder.h>
#include <android/binder_parcel.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <android-base/properties.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>

using aidl::android::hardware::biometrics::fingerprint::ISessionCallback;
using android::base::GetProperty;

namespace {

static const char* kFodNode = "/sys/kernel/oplus_display/notify_fppress";
static const char* kFpStateNode = "/sys/kernel/oplus_display/fp_state";

static bool gMonitorRunning = false;
static pthread_t gMonitorThread;
static bool gPressed = false;
static bool gAuthSessionActive = false;
static pthread_mutex_t gMutex = PTHREAD_MUTEX_INITIALIZER;

static void writeFodNode(const char* val) {
    int fd = open(kFodNode, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return;
    write(fd, val, strlen(val));
    close(fd);
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

static bool isPressed() {
    pthread_mutex_lock(&gMutex);
    bool pressed = gPressed;
    pthread_mutex_unlock(&gMutex);
    return pressed;
}

static void setAuthSessionActive(bool active) {
    pthread_mutex_lock(&gMutex);
    gAuthSessionActive = active;
    pthread_mutex_unlock(&gMutex);
}

static bool isAuthSessionActive() {
    pthread_mutex_lock(&gMutex);
    bool active = gAuthSessionActive;
    pthread_mutex_unlock(&gMutex);
    return active;
}

static bool readFpState(int fd, int& x, int& y, int& state) {
    char buffer[128];
    if (lseek(fd, 0, SEEK_SET) < 0) return false;
    ssize_t len = read(fd, buffer, sizeof(buffer) - 1);
    if (len <= 0) return false;
    buffer[len] = '\0';
    return sscanf(buffer, "%d,%d,%d", &x, &y, &state) == 3;
}

static void* monitorThread(void* /*arg*/) {
    int fd = open(kFpStateNode, O_RDONLY);
    if (fd < 0) return nullptr;

    int lastState = 0, x, y, state;
    readFpState(fd, x, y, state);
    lastState = state;

    while (gMonitorRunning) {
        usleep(20000);  // 20ms polling

        if (readFpState(fd, x, y, state) && state != lastState) {
            // First touch activates session
            if (state > 0 && !isAuthSessionActive()) {
                setAuthSessionActive(true);
            }

            // Only control light if session is active
            if (isAuthSessionActive()) {
                if (state > 0 && !isPressed()) {
                    setPressed(true);
                } else if (state == 0 && isPressed()) {
                    setPressed(false);
                }
            }

            lastState = state;
        }
    }

    close(fd);
    return nullptr;
}

static void startMonitor() {
    if (gMonitorRunning) return;

    std::string sensorType = GetProperty("persist.vendor.fingerprint.sensor_type", "");
    if (sensorType != "optical") return;
    if (access(kFpStateNode, R_OK) != 0) return;

    gMonitorRunning = true;

    if (pthread_create(&gMonitorThread, nullptr, monitorThread, nullptr) == 0) {
        pthread_setname_np(gMonitorThread, "FodMonitor");
    } else {
        gMonitorRunning = false;
    }
}

} // namespace

extern "C"
binder_status_t AIBinder_transact(AIBinder* binder, transaction_code_t code,
                                  AParcel** in, AParcel** out, binder_flags_t flags) {
    using TransactFn = binder_status_t (*)(AIBinder*, transaction_code_t, AParcel**, AParcel**, binder_flags_t);
    static auto orig = (TransactFn)dlsym(RTLD_NEXT, "AIBinder_transact");
    if (!orig) return STATUS_UNKNOWN_ERROR;

    // Detect authentication success or error - end session
    if (code == ISessionCallback::TRANSACTION_onAuthenticationSucceeded ||
        code == ISessionCallback::TRANSACTION_onError) {
        setPressed(false);
        setAuthSessionActive(false);
    }

    return orig(binder, code, in, out, flags);
}

__attribute__((constructor))
static void init() {
    startMonitor();
}

__attribute__((destructor))
static void cleanup() {
    if (gMonitorRunning) {
        gMonitorRunning = false;
        pthread_join(gMonitorThread, nullptr);
    }
    if (isPressed()) {
        setPressed(false);
    }
}
