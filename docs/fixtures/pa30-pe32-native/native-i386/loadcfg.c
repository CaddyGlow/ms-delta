extern const unsigned char branch_and_lock_code[512];
const void * const lock_prefix_table[] = { branch_and_lock_code + 64, 0 };
#pragma pack(push, 4)
struct LoadConfig32 { unsigned prefix[8]; const void * const * LockPrefixTable; unsigned suffix[9]; };
#pragma pack(pop)
__declspec(selectany) const struct LoadConfig32 _load_config_used = { {72, 0, 0, 0, 0, 0, 0, 0}, lock_prefix_table, {0, 0, 0, 0, 0, 0, 0, 0, 0} };
