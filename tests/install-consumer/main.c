#include <forgebit/forgebit.h>

int main(void) {
    forgebit_verify_options options;
    forgebit_verify_options_init(&options);
    if (options.struct_size != sizeof(options)) return 1;

    forgebit_verifier *verifier = forgebit_verifier_create();
    if (verifier == NULL) return 1;

    forgebit_verifier_destroy(verifier);
    return 0;
}
