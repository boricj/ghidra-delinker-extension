/*
 * Intentionally relies on a relocation with a negative addend that points
 * outside the original symbol footprint.
 */

#include <stdio.h>

extern const int s_digits[10];
const int * const s_ascii_digit_bias = s_digits - '0';

unsigned int parse_decimal(const char *s) {
    unsigned int value = 0;

	while (*s != '\0') {
		value = (value * 10) + s_ascii_digit_bias[(unsigned char) *s];
		s++;
	}

    return value;
}

int main(void) {
    if (parse_decimal("0") != 0u) {
        return 1;
    }
    if (parse_decimal("123") != 123u) {
        return 2;
    }
    if (parse_decimal("65535") != 65535u) {
        return 3;
    }

    puts("All tests passed.");
    return 0;
}
