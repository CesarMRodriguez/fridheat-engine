#include <jni.h>
#include <string>

int counter = 0;

extern "C" JNIEXPORT jstring

JNICALL
Java_com_example_mynativeapplication_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_mynativeapplication_MainActivity_getCounterFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    return counter;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_mynativeapplication_MainActivity_incrementCounter(
        JNIEnv* env,
        jobject /* this */) {
    counter++;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_mynativeapplication_MainActivity_decrementCounter(
        JNIEnv* env,
        jobject /* this */) {
    counter--;
}