#include <ctype.h>
#include <stdio.h>

typedef struct {
    int (*matches)(int);
    char flag;
} ascii_property;

const int NUM_ASCII_PROPERTIES = 10;
const ascii_property s_ascii_properties[] = {
    { isgraph, 'g', },
    { isprint, 'p', },
    { iscntrl, 'c', },
    { isspace, 's', },
    { ispunct, '!', },
    { isalnum, 'A', },
    { isalpha, 'a', },
    { isdigit, 'd', },
    { isupper, 'U', },
    { islower, 'l', },
};

int COLUMNS = 4;

void print_number(int num) {
    int n;

    for (n = 3; n >= 0; n--) {
        int digit = (num >> (4 * n)) % 16;

        if (digit < 10)
            putchar('0' + digit);
        else
            putchar('a' + digit - 10);
    }
}

void print_ascii_entry(char character, const ascii_property properties[], int num_ascii_properties) {
    int k;

    print_number(character);
    putchar(' ');

    if (isgraph(character))
        putchar(character);
    else
        putchar(' ');
    putchar(' ');

    for (k = 0; k < num_ascii_properties; k++) {
        const ascii_property *property = &properties[k];

        if (property->matches(character))
            putchar(property->flag);
        else
            putchar(' ');
    }
}

int main() {
    int i;

    for (i = 0; i < 128; i++) {
        int x = i % COLUMNS;
        int y = i / COLUMNS;
        int character = x * 128 / COLUMNS + y;

        print_ascii_entry(character, s_ascii_properties, NUM_ASCII_PROPERTIES);

        putchar(i % COLUMNS == COLUMNS - 1 ? '\n' : '\t');
    }

    return 0;
}
