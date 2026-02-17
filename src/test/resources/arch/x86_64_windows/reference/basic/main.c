long long global_value = 0x1122334455667788LL;
long long *global_ptr = &global_value;

__attribute__((noinline))
long long helper(long long x) {
	return x + global_value;
}

int entry(void) {
	return (int) helper(*global_ptr);
}
