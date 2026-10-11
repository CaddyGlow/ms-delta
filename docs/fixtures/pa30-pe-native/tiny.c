#ifndef REVISION
#define REVISION 1
#endif
__declspec(dllexport) volatile unsigned long seed = REVISION;
#ifdef SHIFT
__declspec(noinline) __declspec(dllexport) unsigned long leading(unsigned long input) {
    volatile unsigned long words[32];
    for (unsigned long i = 0; i < 32; ++i) words[i] = input * (i + 1);
    return words[input & 31];
}
#endif
__declspec(noinline) __declspec(dllexport) unsigned long transform(unsigned long input) {
    volatile unsigned long values[16];
    for (unsigned long i = 0; i < 16; ++i) values[i] = input + i + REVISION;
    return values[input & 15] ^ 0x5071;
}
__declspec(dllexport) unsigned long (*volatile pointer)(unsigned long) = transform;
void mainCRTStartup(void) { seed = pointer(seed); }
