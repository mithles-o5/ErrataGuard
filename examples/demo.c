/*
 * ErrataGuard Demonstration C Program
 *
 * Can be cross-compiled with:
 *   aarch64-linux-gnu-gcc -g -O0 -o firmware.elf examples/demo.c
 */

int process_data(int x)
{
    return x + 1;
}

int main(void)
{
    return process_data(41);
}
