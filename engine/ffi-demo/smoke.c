/* smoke.c — test C réel de l'ABI optiCombat : scanne les fichiers passés en
 * argument, imprime verdict + JSON. Sert de preuve que le cdylib est
 * consommable depuis du C pur (et donc depuis le P/Invoke C#). */
#include <stdio.h>
#include "opticombat.h"

static const char *verdict_name(int code) {
    switch (code) {
        case OC_CLEAN:      return "CLEAN";
        case OC_SUSPICIOUS: return "SUSPICIOUS";
        case OC_MALICIOUS:  return "MALICIOUS";
        default:            return "ERROR";
    }
}

int main(int argc, char **argv) {
    printf("optiCombat engine version: %s\n", opticombat_version());
    int worst = OC_CLEAN;
    for (int i = 1; i < argc; i++) {
        int code = opticombat_scan_path(argv[i]);
        char *json = opticombat_scan_json(argv[i]);
        printf("[%s] %s\n  %s\n", argv[i], verdict_name(code), json ? json : "(null)");
        if (json) opticombat_string_free(json);
        if (code > worst) worst = code;
    }
    return worst;
}
